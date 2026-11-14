#!/usr/bin/env node
// Rule engine vs the s6-secrets-pico model vs their union, on the same texts.
// Dev-only measurement script behind docs/model-comparison.md. The rule side
// is secretgate's own scanner, imported from the TypeScript sources through
// Node's type stripping (Node >= 22.18); the model side is the engine host
// scripts/sky-wasm.mjs and the model adapter scripts/s6-secrets-pico.mjs.
//
//   node scripts/model-compare.mjs --wasm sky_web_bg.wasm --model s6-secrets-pico.gguf \
//     [--bench secret_bench.jsonl] [--clean DIR_OR_FILE]... [--max-files 400] [--max-chunks 100] \
//     [--typical FILE] [--fresh-runs 9] [--parity sky_web.js] [--census] [--out report.json] \
//     [--chunk-lines 7] [--chunk-chars 300] [--no-material]
//
// --bench   skycmd's data/secrets/secret_bench.jsonl (records of the test split)
// --clean   real text: its files the rule engine finds clean are cut into model
//           chunks, and every chunk the model flags is a false positive
// --census  also run the rule engine alone over EVERY file of the --clean roots
//           (no sampling) and list its findings: the population a model that
//           judges rule candidates would see
// --parity  the engine's own wasm-bindgen glue, to check that sky-wasm.mjs returns
//           the same probabilities on the first 200 bench records (runs that JS)
// Nothing here touches the network. It writes --out, and runs the built bundle
// as a hook inside a temporary HOME that it removes afterwards.
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { registerHooks } from "node:module";
import { extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as pico from "./s6-secrets-pico.mjs";
import * as host from "./sky-wasm.mjs";

if (typeof registerHooks !== "function") {
  console.error("model-compare: needs Node >= 22.18 (module.registerHooks and type stripping)");
  process.exit(2);
}
// The sources import `./x.js`; the file on disk is `./x.ts`.
registerHooks({
  resolve(spec, ctx, next) {
    try {
      return next(spec, ctx);
    } catch (err) {
      if (spec.startsWith(".") && spec.endsWith(".js")) return next(`${spec.slice(0, -3)}.ts`, ctx);
      throw err;
    }
  },
});

const root = resolve(fileURLToPath(import.meta.url), "../..");
const t0 = performance.now();

// ---------------------------------------------------------------- args
const args = process.argv.slice(2);
const opt = { clean: [], maxFiles: 400, maxChunks: 100, freshRuns: 9, thresholds: [0.5, 0.9, 0.99, 0.999] };
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  const v = () => args[++i];
  if (a === "--wasm") opt.wasm = v();
  else if (a === "--model") opt.model = v();
  else if (a === "--bench") opt.bench = v();
  else if (a === "--clean") opt.clean.push(v());
  else if (a === "--max-files") opt.maxFiles = Number(v());
  else if (a === "--max-chunks") opt.maxChunks = Number(v());
  else if (a === "--typical") opt.typical = v();
  else if (a === "--fresh-runs") opt.freshRuns = Number(v());
  else if (a === "--chunk-lines") opt.chunkLines = Number(v());
  else if (a === "--chunk-chars") opt.chunkChars = Number(v());
  else if (a === "--no-material") opt.skipMaterial = true;
  else if (a === "--parity") opt.parity = v();
  else if (a === "--census") opt.census = true;
  else if (a === "--out") opt.out = v();
  else if (a === "--child") opt.child = v();
  else {
    console.error(`model-compare: unknown argument ${a}`);
    process.exit(2);
  }
}
if (!opt.wasm || !opt.model) {
  console.error("usage: model-compare.mjs --wasm FILE --model FILE [--bench FILE] [--clean DIR]... [--out FILE]");
  process.exit(2);
}
const readPinned = () => {
  const wasm = readFileSync(opt.wasm);
  const gguf = readFileSync(opt.model);
  const hashes = { wasm: host.sha256Hex(wasm), model: host.sha256Hex(gguf) };
  if (hashes.wasm !== host.ENGINE_ASSET.sha256 || hashes.model !== pico.ASSET.sha256) {
    console.error(`model-compare: the files are not the pinned assets (${JSON.stringify(hashes)})`);
    process.exit(2);
  }
  return { wasm, gguf, hashes };
};

// ---------------------------------------------------------------- child modes (fresh-process latency)
// What a hook process would pay. `--child rules`: import the rule engine, scan
// one chunk. `--child model`: the same, then read and verify both files,
// compile the engine, load the model and take one decision.
if (opt.child) {
  const sample = "DATABASE_HOST=db.internal\nDATABASE_PORT=5432\nLOG_LEVEL=info";
  const marks = {};
  const { scan } = await import(join(root, "src/engine/scanner.ts"));
  marks.importedMs = performance.now();
  scan(sample, { pragmas: false });
  marks.rulesDoneMs = performance.now();
  if (opt.child === "model") {
    const { wasm, gguf } = readPinned();
    marks.verifiedMs = performance.now();
    const engine = host.loadSkyEngine(wasm, gguf);
    marks.loadedMs = performance.now();
    pico.score(engine, sample);
    marks.firstDecisionMs = performance.now();
  }
  process.stdout.write(JSON.stringify(marks));
  process.exit(0);
}

// ---------------------------------------------------------------- shared
const { scan } = await import(join(root, "src/engine/scanner.ts"));
const CHUNK_MAX_LINES = opt.chunkLines ?? pico.CHUNK_MAX_LINES;
const CHUNK_MAX_CHARS = opt.chunkChars ?? pico.CHUNK_MAX_CHARS;
const chunkText = (text) => pico.units(text, CHUNK_MAX_LINES, CHUNK_MAX_CHARS);
const { wasm: wasmBytes, gguf: ggufBytes, hashes } = readPinned();
const loadStart = performance.now();
const engine = host.loadSkyEngine(wasmBytes, ggufBytes);
const loadMs = performance.now() - loadStart;
const decisionUs = [];
const pOf = (text) => {
  const a = performance.now();
  const p = pico.score(engine, text);
  decisionUs.push((performance.now() - a) * 1000);
  return p;
};
// A stricter rule tried as a mitigation, two more questions per flagged chunk:
// P(secret) >= 0.9 AND the kind question answers "secret" AND the service
// question does not answer "none".
const argmax = (v) => v.indexOf(Math.max(...v));
const confirmed = (text) => {
  const k = engine.decide(pico.KIND_QUESTION.t, pico.KIND_QUESTION.ins, pico.KIND_QUESTION.opts, text).probs;
  const s = engine.decide(pico.SERVICE_QUESTION.t, pico.SERVICE_QUESTION.ins, pico.SERVICE_QUESTION.opts, text).probs;
  return argmax(k) === 0 && argmax(s) !== pico.SERVICE_QUESTION.opts.length - 1;
};
// A whole text through the chunker: the max P(secret) over its chunks, and
// whether any chunk passes the stricter rule.
function textScore(text) {
  let p = 0;
  let conf = false;
  for (const c of chunkText(text)) {
    const q = pOf(c.text);
    p = Math.max(p, q);
    if (q >= 0.9 && !conf) conf = confirmed(c.text);
  }
  return { p, confirmed: conf };
}
const rulesHit = (text) => scan(text, { pragmas: false }).length > 0;

const ratio = (a, b) => (b === 0 ? null : a / b);
function confusion(items, predict) {
  let tp = 0;
  let fp = 0;
  let fn = 0;
  let tn = 0;
  for (const it of items) {
    const y = predict(it);
    if (it.label && y) tp++;
    else if (!it.label && y) fp++;
    else if (it.label) fn++;
    else tn++;
  }
  return { tp, fp, fn, tn, recall: ratio(tp, tp + fn), precision: ratio(tp, tp + fp), accuracy: ratio(tp + tn, items.length) };
}
const quantile = (xs, q) => {
  const s = [...xs].sort((a, b) => a - b);
  return s.length === 0 ? null : s[Math.min(s.length - 1, Math.floor(q * s.length))];
};
const median = (xs) => quantile(xs, 0.5);
const report = {
  date: new Date().toISOString(),
  node: process.version,
  hashes,
  engineLoadMs: loadMs,
  chunking: { maxLines: CHUNK_MAX_LINES, maxChars: CHUNK_MAX_CHARS },
  thresholds: opt.thresholds,
};
const fmt = (x, d = 4) => (x === null || x === undefined ? "n/a" : typeof x === "number" ? x.toFixed(d) : String(x));
const log = (s = "") => console.log(s);

// ---------------------------------------------------------------- 0. host parity
// sky-wasm.mjs against the engine's own glue, on the same records.
if (opt.parity && opt.bench) {
  const glue = await import(resolve(opt.parity));
  glue.initSync({ module: wasmBytes });
  const ref = new glue.Engine(new Uint8Array(ggufBytes));
  ref.setExitThreshold(1);
  const rows = readFileSync(opt.bench, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l))
    .filter((r) => r.split === "test")
    .slice(0, 200);
  let maxAbsDiff = 0;
  let argmaxAgree = 0;
  for (const r of rows) {
    const a = JSON.parse(ref.decide(r.t, r.ins, JSON.stringify(r.opts), r.state)).probs;
    const b = engine.decide(r.t, r.ins, r.opts, r.state).probs;
    for (let i = 0; i < a.length; i++) maxAbsDiff = Math.max(maxAbsDiff, Math.abs(a[i] - b[i]));
    if (argmax(a) === argmax(b)) argmaxAgree++;
  }
  report.parity = { records: rows.length, maxAbsDiff, argmaxAgree };
  console.log(`== 0. host parity with the engine's own glue: ${rows.length} records, max |diff| ${maxAbsDiff}, same answer on ${argmaxAgree}\n`);
}

// ---------------------------------------------------------------- 1. secret_bench
if (opt.bench) {
  const rows = readFileSync(opt.bench, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l))
    .filter((r) => r.split === "test" && r.src.startsWith("secret_bench"));
  const kindOf = new Map(rows.filter((r) => r.src.endsWith(":kind")).map((r) => [r.state, r.target.indexOf(1)]));
  const KINDS = ["secret", "test", "public", "placeholder", "other"];
  const items = rows
    .filter((r) => r.src.endsWith(":secret"))
    .map((r) => {
      const kind = KINDS[kindOf.get(r.state)] ?? "unknown";
      return { label: r.target[1] === 1, kind, rules: rulesHit(r.state), ...textScore(r.state) };
    });
  const out = { texts: items.length, positives: items.filter((i) => i.label).length, rules: confusion(items, (i) => i.rules), model: {}, union: {} };
  for (const t of opt.thresholds) {
    out.model[t] = confusion(items, (i) => i.p >= t);
    out.union[t] = confusion(items, (i) => i.rules || i.p >= t);
  }
  out.modelConfirmed = confusion(items, (i) => i.confirmed);
  // Where each side errs, by the bench's kind of value.
  out.rulesFalsePositivesByKind = {};
  out.rulesMissesByKind = {};
  for (const i of items) {
    if (i.rules && !i.label) out.rulesFalsePositivesByKind[i.kind] = (out.rulesFalsePositivesByKind[i.kind] ?? 0) + 1;
    if (!i.rules && i.label) out.rulesMissesByKind[i.kind] = (out.rulesMissesByKind[i.kind] ?? 0) + 1;
  }
  // secretgate redacts test keys too (a sandbox key is still a credential):
  // the same texts scored against "secret or test credential".
  const cred = items.map((i) => ({ ...i, label: i.kind === "secret" || i.kind === "test" }));
  out.credentialLabel = { positives: cred.filter((i) => i.label).length, rules: confusion(cred, (i) => i.rules), model: confusion(cred, (i) => i.p >= 0.5) };
  report.bench = out;
  log("== 1. secret_bench (synthetic, same generator as the model's training data: favours the model)");
  log(`texts ${out.texts}, usable-secret positives ${out.positives}`);
  log("engine            recall  precision accuracy   tp   fp   fn   tn");
  const row = (name, c) =>
    log(`${name.padEnd(17)} ${fmt(c.recall)}  ${fmt(c.precision)}    ${fmt(c.accuracy)}  ${String(c.tp).padStart(4)} ${String(c.fp).padStart(4)} ${String(c.fn).padStart(4)} ${String(c.tn).padStart(4)}`);
  row("rules", out.rules);
  for (const t of opt.thresholds) row(`model p>=${t}`, out.model[t]);
  for (const t of opt.thresholds) row(`union p>=${t}`, out.union[t]);
  row("model confirmed", out.modelConfirmed);
  log(`rules false positives by kind: ${JSON.stringify(out.rulesFalsePositivesByKind)}; misses by kind: ${JSON.stringify(out.rulesMissesByKind)}`);
  log(`label "secret or test credential" (${out.credentialLabel.positives} positives):`);
  row("rules", out.credentialLabel.rules);
  row("model p>=0.5", out.credentialLabel.model);
  log();
}

// ---------------------------------------------------------------- 2. secretgate's own material
if (!opt.skipMaterial) {
  const { FAKE } = await import(join(root, "tests/fixtures/fake-tokens.ts"));
  // tests/e2e/real-scenarios.mjs builds its token with this LCG (seed 7).
  const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let seed = 7;
  const rand = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff);
  const scenarioToken = "ghp" + "_" + Array.from({ length: 36 }, () => ALNUM[rand() % ALNUM.length]).join("");
  // Each fixture token in the contexts a coding agent shows it in.
  const contexts = [
    ["env", (v) => `# service settings\nAPP_ENV=production\nSERVICE_TOKEN=${v}\nLOG_LEVEL=info`],
    ["json", (v) => `{\n  "name": "deploy",\n  "token": "${v}",\n  "retries": 3\n}`],
    ["yaml", (v) => `service:\n  region: eu-west-1\n  credentials:\n    key: ${v}`],
    ["code", (v) => `import { Client } from "./client";\n\nconst token = "${v}";\nexport const client = new Client(token);`],
    ["shell", (v) => `cd /srv/app\nexport API_TOKEN=${v}\n./run.sh --verbose`],
    ["log", (v) => `2026-11-14T10:02:11Z INFO request started\n2026-11-14T10:02:11Z DEBUG using credential ${v}\n2026-11-14T10:02:12Z INFO done`],
    ["prose", (v) => `some text before\n${v}\nafter`],
  ];
  const items = [];
  for (const [name, value] of Object.entries(FAKE)) {
    for (const [ctx, wrap] of contexts) {
      // A multi-line private key reads oddly inside a one-line value: keep it as a block.
      const text = name === "privateKey" ? (ctx === "prose" ? `some text before\n${value}\nafter` : `# key file\n${value}`) : wrap(value);
      items.push({ source: `fake-tokens:${name}:${ctx}`, text });
    }
  }
  items.push({ source: "real-scenarios:pipe", text: `TOKEN=${scenarioToken}\n` });
  items.push({ source: "real-scenarios:post-tool-use", text: `T=${scenarioToken}` });
  const scored = items.map((i) => ({ ...i, rules: rulesHit(i.text), ...textScore(i.text) }));
  const rulesPos = scored.filter((i) => i.rules);
  const out = { texts: scored.length, rulesFlagged: rulesPos.length, modelAlsoFlags: {}, modelOnly: {}, rulesMissed: scored.filter((i) => !i.rules).map((i) => i.source) };
  for (const t of opt.thresholds) {
    out.modelAlsoFlags[t] = rulesPos.filter((i) => i.p >= t).length;
    out.modelOnly[t] = scored.filter((i) => !i.rules && i.p >= t).map((i) => i.source);
  }
  const byToken = {};
  for (const i of rulesPos) {
    const k = i.source.split(":")[1];
    byToken[k] ??= { rules: 0, model90: 0, minP: 1 };
    byToken[k].rules++;
    if (i.p >= 0.9) byToken[k].model90++;
    byToken[k].minP = Math.min(byToken[k].minP, i.p);
  }
  out.byToken = byToken;
  out.modelConfirmedOfRules = rulesPos.filter((i) => i.confirmed).length;
  out.items = scored.map(({ source, rules, p, confirmed }) => ({ source, rules, p, confirmed }));
  out.modelMissesAt90 = rulesPos.filter((i) => i.p < 0.9).map((i) => i.source);
  // The zero-false-positive fixtures of tests/fixtures/fp-corpus: clean by test.
  const corpusDir = join(root, "tests/fixtures/fp-corpus");
  const corpus = readdirSync(corpusDir).map((f) => {
    const text = readFileSync(join(corpusDir, f), "utf8");
    const ps = chunkText(text).map((c) => pOf(c.text));
    return { file: f, rules: rulesHit(text), chunks: ps.length, maxP: Math.max(0, ...ps), flagged90: ps.filter((p) => p >= 0.9).length };
  });
  out.fpCorpus = corpus;
  report.secretgate = out;
  log("== 2. secretgate's own material (fake-tokens fixtures in 7 contexts, real-scenarios tokens)");
  log(`texts ${out.texts}; the rules flag ${out.rulesFlagged}; missed by the rules: ${out.rulesMissed.join(", ") || "none"}`);
  for (const t of opt.thresholds) log(`model p>=${t}: flags ${out.modelAlsoFlags[t]}/${out.rulesFlagged} of the rule detections; model-only: ${out.modelOnly[t].join(", ") || "none"}`);
  log(`model confirmed: flags ${out.modelConfirmedOfRules}/${out.rulesFlagged} of the rule detections`);
  log(`rule detections the model misses at 0.9: ${out.modelMissesAt90.join(", ")}`);
  for (const [k, v] of Object.entries(byToken)) log(`  ${k.padEnd(16)} rules ${v.rules}  model>=0.9 ${v.model90}  min p ${fmt(v.minP)}`);
  log("tests/fixtures/fp-corpus (zero rule findings by test):");
  for (const c of corpus) log(`  ${c.file.padEnd(24)} rules ${c.rules ? "HIT" : "clean"}  chunks ${c.chunks}  max p ${fmt(c.maxP)}  chunks p>=0.9 ${c.flagged90}`);
  log();
}

// ---------------------------------------------------------------- 3. false positives on real, clean text
const EXT = new Set([".ts", ".js", ".mjs", ".cjs", ".json", ".md", ".toml", ".yml", ".yaml", ".rs"]);
const SKIP = new Set([".git", "target", ".claude", "coverage"]);
function* walk(dir) {
  if (statSync(dir).isFile()) {
    yield dir;
    return;
  }
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (e.isSymbolicLink()) continue;
    const full = join(dir, e.name);
    if (e.isDirectory()) {
      if (!SKIP.has(e.name)) yield* walk(full);
    } else if (e.isFile() && EXT.has(extname(e.name))) yield full;
  }
}
// Deterministic sample: a seeded shuffle of the sorted list.
function sample(list, n, seedStr) {
  let s = [...seedStr].reduce((h, c) => (h * 31 + c.charCodeAt(0)) >>> 0, 7);
  const r = () => (s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32;
  const a = [...list].sort();
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(r() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a.slice(0, n);
}
const rulesChunkUs = [];
if (opt.clean.length > 0) {
  const roots = [];
  const flaggedSamples = [];
  const allP = [];
  // Every flagged chunk, kept by a seeded reservoir for an unbiased look at
  // what the model flags (the top of the list is all p = 1.0000).
  const reservoir = [];
  let seenFlagged = 0;
  let rs = 12345;
  const rr = () => (rs = (rs * 1664525 + 1013904223) >>> 0) / 2 ** 32;
  for (const dir of opt.clean) {
    const files = sample([...walk(dir)], opt.maxFiles, dir);
    const r = { dir, files: 0, excludedByRules: 0, chunks: 0, chunkFlags: {}, fileFlags: {}, byExt: {} };
    for (const t of opt.thresholds) {
      r.chunkFlags[t] = 0;
      r.chunkConfirmed = 0;
      r.fileConfirmed = 0;
      r.fileFlags[t] = 0;
    }
    for (const file of files) {
      const st = statSync(file);
      if (st.size === 0 || st.size > 256 * 1024) continue;
      const buf = readFileSync(file);
      if (buf.subarray(0, 8192).includes(0)) continue;
      const text = buf.toString("utf8");
      if (rulesHit(text)) {
        r.excludedByRules++;
        continue;
      }
      r.files++;
      const ext = extname(file);
      r.byExt[ext] ??= { files: 0, chunks: 0, chunks90: 0, files90: 0 };
      r.byExt[ext].files++;
      let maxP = 0;
      let anyConfirmed = false;
      for (const c of chunkText(text).slice(0, opt.maxChunks)) {
        const a = performance.now();
        scan(c.text, { pragmas: false });
        rulesChunkUs.push((performance.now() - a) * 1000);
        const p = pOf(c.text);
        allP.push(p);
        r.chunks++;
        r.byExt[ext].chunks++;
        maxP = Math.max(maxP, p);
        for (const t of opt.thresholds) if (p >= t) r.chunkFlags[t]++;
        if (p >= 0.9 && confirmed(c.text)) {
          r.chunkConfirmed++;
          anyConfirmed = true;
        }
        if (p >= 0.9) {
          r.byExt[ext].chunks90++;
          const item = { file: relative(dir, file) || file, root: dir, line: c.line + 1, p, text: c.text };
          flaggedSamples.push(item);
          seenFlagged++;
          if (reservoir.length < 40) reservoir.push(item);
          else {
            const j = Math.floor(rr() * seenFlagged);
            if (j < 40) reservoir[j] = item;
          }
        }
      }
      for (const t of opt.thresholds) if (maxP >= t) r.fileFlags[t]++;
      if (anyConfirmed) r.fileConfirmed++;
      if (maxP >= 0.9) r.byExt[ext].files90++;
    }
    roots.push(r);
  }
  const total = { files: 0, chunks: 0, chunkFlags: {}, fileFlags: {} };
  for (const t of opt.thresholds) {
    total.chunkFlags[t] = roots.reduce((s, r) => s + r.chunkFlags[t], 0);
    total.fileFlags[t] = roots.reduce((s, r) => s + r.fileFlags[t], 0);
  }
  total.files = roots.reduce((s, r) => s + r.files, 0);
  total.chunkConfirmed = roots.reduce((s, r) => s + r.chunkConfirmed, 0);
  total.fileConfirmed = roots.reduce((s, r) => s + r.fileConfirmed, 0);
  total.chunks = roots.reduce((s, r) => s + r.chunks, 0);
  flaggedSamples.sort((a, b) => b.p - a.p);
  report.clean = {
    roots,
    total,
    pQuantiles: { p50: quantile(allP, 0.5), p90: quantile(allP, 0.9), p99: quantile(allP, 0.99), p999: quantile(allP, 0.999), max: quantile(allP, 1) },
    flaggedTop: flaggedSamples.slice(0, 60),
    flaggedRandom: reservoir,
  };
  log("== 3. false positives on real text the rule engine finds clean (out of distribution)");
  log("root                                                   files  chunks | chunk FP rate at 0.5 / 0.9 / 0.99 / 0.999 | file FP rate at 0.5 / 0.9 / 0.99 / 0.999");
  const rates = (flags, n) => opt.thresholds.map((t) => `${fmt(ratio(flags[t], n), 3)} (${flags[t]})`).join(" / ");
  for (const r of roots)
    log(`${r.dir.padEnd(54)} ${String(r.files).padStart(5)} ${String(r.chunks).padStart(7)} | ${rates(r.chunkFlags, r.chunks)} | ${rates(r.fileFlags, r.files)}  [excluded, rule hit: ${r.excludedByRules}]`);
  log(`${"TOTAL".padEnd(54)} ${String(total.files).padStart(5)} ${String(total.chunks).padStart(7)} | ${rates(total.chunkFlags, total.chunks)} | ${rates(total.fileFlags, total.files)}`);
  log(`model confirmed (p>=0.9, kind "secret", service not "none"): chunks ${fmt(ratio(total.chunkConfirmed, total.chunks), 3)} (${total.chunkConfirmed}), files ${fmt(ratio(total.fileConfirmed, total.files), 3)} (${total.fileConfirmed})`);
  log(`P(secret) over clean chunks: ${JSON.stringify(report.clean.pQuantiles)}`);
  log("by extension (p>=0.9):");
  const ext = {};
  for (const r of roots)
    for (const [k, v] of Object.entries(r.byExt)) {
      ext[k] ??= { files: 0, chunks: 0, chunks90: 0, files90: 0 };
      for (const f of Object.keys(v)) ext[k][f] += v[f];
    }
  for (const [k, v] of Object.entries(ext)) log(`  ${k.padEnd(6)} files ${v.files} (flagged ${v.files90})  chunks ${v.chunks} (flagged ${v.chunks90})`);
  log("highest-scoring clean chunks (first 25; text with whitespace collapsed, cut at 140 chars):");
  for (const s of flaggedSamples.slice(0, 25)) log(`  p=${fmt(s.p, 5)} ${s.file}:${s.line}  ${s.text.replace(/\s+/g, " ").slice(0, 140)}`);
  log("a seeded random sample of the chunks flagged at p >= 0.9 (25 of 40 kept):");
  for (const s of reservoir.slice(0, 25)) log(`  p=${fmt(s.p, 5)} ${s.file}:${s.line}  ${s.text.replace(/\s+/g, " ").slice(0, 140)}`);
  log();
}

// ---------------------------------------------------------------- 5. rule findings on real files
// The hooks scan tool output with no source path (no path allowlist) and no
// pragmas; so does this census. Values are never printed: rule, place, length
// and entropy only.
if (opt.census && opt.clean.length > 0) {
  const out = { files: 0, filesWithFindings: 0, findings: 0, byRule: {}, perFile: {}, list: [], scanMs: [] };
  for (const dir of opt.clean) {
    for (const file of walk(dir)) {
      const st = statSync(file);
      if (st.size === 0 || st.size > 2 * 1024 * 1024) continue;
      const buf = readFileSync(file);
      if (buf.subarray(0, 8192).includes(0)) continue;
      const text = buf.toString("utf8");
      const a = performance.now();
      const found = scan(text, { pragmas: false });
      out.scanMs.push(performance.now() - a);
      out.files++;
      if (found.length === 0) continue;
      out.filesWithFindings++;
      out.findings += found.length;
      out.perFile[found.length] = (out.perFile[found.length] ?? 0) + 1;
      for (const f of found) {
        out.byRule[f.ruleId] = (out.byRule[f.ruleId] ?? 0) + 1;
        out.list.push({ root: dir, file: relative(dir, file) || file, line: f.line + 1, ruleId: f.ruleId, length: f.secret.length, entropy: Number(f.entropy.toFixed(2)) });
      }
    }
  }
  const ms = out.scanMs;
  out.scanMs = { median: median(ms), p95: quantile(ms, 0.95), max: quantile(ms, 1) };
  report.census = out;
  log("== 5. rule findings on every file of the --clean roots (rules only, as the hooks scan tool output)");
  log(`files ${out.files}, with findings ${out.filesWithFindings}, findings ${out.findings}; findings per file with any: ${JSON.stringify(out.perFile)}`);
  log(`by rule: ${JSON.stringify(out.byRule)}`);
  log(`rule scan per file: median ${fmt(out.scanMs.median, 2)} ms, p95 ${fmt(out.scanMs.p95, 2)} ms, max ${fmt(out.scanMs.max, 1)} ms`);
  for (const f of out.list.slice(0, 80)) log(`  ${f.ruleId.padEnd(28)} ${f.file}:${f.line}  len ${f.length} entropy ${f.entropy}`);
  log();
}

// ---------------------------------------------------------------- 4. latency
if (opt.freshRuns > 0) {
  const out = {};
  out.warmDecisionUs = { n: decisionUs.length, median: median(decisionUs), p95: quantile(decisionUs, 0.95), max: quantile(decisionUs, 1) };
  out.rulesPerChunkUs = { n: rulesChunkUs.length, median: median(rulesChunkUs), p95: quantile(rulesChunkUs, 0.95) };
  const typical = opt.typical ?? join(root, "src/engine/scanner.ts");
  const text = readFileSync(typical, "utf8");
  const reps = 5;
  const rulesMs = [];
  const modelMs = [];
  for (let i = 0; i < reps; i++) {
    let a = performance.now();
    scan(text, { pragmas: false });
    rulesMs.push(performance.now() - a);
    a = performance.now();
    for (const c of chunkText(text)) pico.score(engine, c.text);
    modelMs.push(performance.now() - a);
  }
  out.typicalFile = { file: relative(root, typical), bytes: Buffer.byteLength(text), lines: text.split("\n").length, chunks: chunkText(text).length, rulesMs: median(rulesMs), modelMs: median(modelMs) };
  const fresh = (mode) => {
    const runs = [];
    for (let i = 0; i < opt.freshRuns; i++) {
      const a = performance.now();
      const r = spawnSync(process.execPath, [fileURLToPath(import.meta.url), "--wasm", opt.wasm, "--model", opt.model, "--child", mode], { encoding: "utf8" });
      const wall = performance.now() - a;
      if (r.status !== 0) throw new Error(`child ${mode} failed: ${r.stderr}`);
      runs.push({ wall, ...JSON.parse(r.stdout) });
    }
    const m = (k) => median(runs.map((x) => x[k]).filter((x) => x !== undefined));
    return { runs: runs.length, wallMs: m("wall"), importedMs: m("importedMs"), rulesDoneMs: m("rulesDoneMs"), verifiedMs: m("verifiedMs"), loadedMs: m("loadedMs"), firstDecisionMs: m("firstDecisionMs") };
  };
  // The real thing for the rules side: the built bundle as a Claude Code
  // PostToolUse hook on a clean shell output, in a throwaway HOME.
  {
    const home = mkdtempSync(join(tmpdir(), "sg-model-compare-"));
    const proj = join(home, "proj");
    mkdirSync(join(proj, ".git"), { recursive: true });
    const env = { ...process.env, HOME: home, USERPROFILE: home, SECRETGATE_HOME: join(home, ".secretgate") };
    delete env.SECRETGATE_DISABLE;
    delete env.CLAUDE_PROJECT_DIR;
    const input = JSON.stringify({
      session_id: "model-compare",
      cwd: proj,
      tool_name: "Bash",
      tool_input: { command: "cat app.env" },
      tool_response: { stdout: "DATABASE_HOST=db.internal\nDATABASE_PORT=5432\nLOG_LEVEL=info", stderr: "" },
    });
    const runs = [];
    try {
      for (let i = 0; i <= 25; i++) {
        const a = performance.now();
        const r = spawnSync(process.execPath, [join(root, "scripts/secretgate.mjs"), "hook", "claude-code", "post-tool-use"], { input, env, cwd: proj, encoding: "utf8" });
        if (r.status !== 0) throw new Error(`bundle hook failed: ${r.stderr}`);
        if (i > 0) runs.push(performance.now() - a); // the first run warms the file cache
      }
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
    out.bundleHook = { runs: runs.length, medianMs: median(runs), p95Ms: quantile(runs, 0.95) };
  }
  out.freshRules = fresh("rules");
  out.freshModel = fresh("model");
  report.latency = out;
  log("== 4. latency (Node, this machine; nice 19 while other work runs)");
  log(`engine compile + model load in this process: ${fmt(loadMs, 1)} ms`);
  log(`warm decision (secret question, one chunk): median ${fmt(out.warmDecisionUs.median / 1000, 3)} ms, p95 ${fmt(out.warmDecisionUs.p95 / 1000, 3)} ms over ${out.warmDecisionUs.n}`);
  log(`rule engine on the same chunks: median ${fmt(out.rulesPerChunkUs.median / 1000, 3)} ms, p95 ${fmt(out.rulesPerChunkUs.p95 / 1000, 3)} ms`);
  const tf = out.typicalFile;
  log(`typical file ${tf.file} (${tf.bytes} bytes, ${tf.lines} lines, ${tf.chunks} chunks): rules ${fmt(tf.rulesMs, 1)} ms, model ${fmt(tf.modelMs, 1)} ms`);
  const f = (x) => `wall ${fmt(x.wallMs, 1)} ms (imports done at ${fmt(x.importedMs, 1)}, rules done at ${fmt(x.rulesDoneMs, 1)}${x.loadedMs ? `, files verified at ${fmt(x.verifiedMs, 1)}, engine loaded at ${fmt(x.loadedMs, 1)}, first decision at ${fmt(x.firstDecisionMs, 1)}` : ""} ms after process start)`;
  log(`built bundle as a PostToolUse hook, clean output, rules only: median ${fmt(out.bundleHook.medianMs, 1)} ms, p95 ${fmt(out.bundleHook.p95Ms, 1)} ms over ${out.bundleHook.runs} runs`);
  log(`fresh process, rules only: ${f(out.freshRules)}`);
  log(`fresh process, rules + model: ${f(out.freshModel)}`);
  log();
}

report.elapsedS = (performance.now() - t0) / 1000;
if (opt.out) writeFileSync(opt.out, JSON.stringify(report, null, 2));
log(`done in ${fmt(report.elapsedS, 1)} s${opt.out ? `, report in ${opt.out}` : ""}`);
