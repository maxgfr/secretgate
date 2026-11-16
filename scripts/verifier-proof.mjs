#!/usr/bin/env node
// The two proofs of the verifier option (docs/verifier.md), against the data
// of skycmd's s6-secrets v2 experiment. Dev-only: not in the bundle, and it
// needs that experiment's data folder (CredData and the frozen files).
//
//   nice -n 19 node scripts/verifier-proof.mjs --data <s6-secrets2 folder> [--split training|validation]...
//   nice -n 19 node scripts/verifier-proof.mjs --data <folder> --e2e --assets <dir> [--build relaxed-simd|simd128]
//   nice -n 19 node scripts/verifier-proof.mjs --data <folder> --clean --assets <dir>
//
// 1. Generator. Runs src/verifier/generator.ts over the files of the CredData
//    TRAINING and VALIDATION repositories, in the order and with the paths of
//    the frozen run (gen/run-trainval.mjs: the files below creddata/, the path
//    below it as source path, --max-bytes 64 MiB, --max-line 1000), and
//    compares the sha256 of its raw export with the frozen files
//    gen/candidates-<split>.raw.jsonl. The export is hashed as it is made and
//    never written. On a mismatch it compares the records one by one and
//    prints, per field, how many differ: never a value.
// 2. End to end (validation). The same records, through the verifier as the
//    option runs it (the pinned assets checked again, the WebAssembly build,
//    tau_f1 from the model file), against the skycmd evaluation: the state
//    the model reads, P(real) and the accepted set.
// 3. Clean text (--clean). The same on the census corpus of
//    docs/model-comparison.md as the data froze it (eval/clean/corpus, the
//    list of gen/clean-corpus.json): the generator with no source path, as the
//    evaluation ran it, and the model's state built with the path and without.
//
// The split guard of the frozen runner stays: only the 116 training and
// validation repositories of splits.json are listed, every listed path is
// checked again, and a test repository stops the run. Nothing here reads a
// test repository, prints a value or a line, or touches the network.
import { createHash } from "node:crypto";
import { createReadStream, readdirSync, readFileSync, statSync } from "node:fs";
import * as nodeModule from "node:module";
import { dirname, join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath, pathToFileURL } from "node:url";

const FROZEN_SHA256 = {
  training: "f1946d905f1cc9d4b77ed789488d4fe4e59c9ee109682bcead4348fb4dfec8b2",
  validation: "15aa997c16ef4a38e62d055441b222f5e390efe4a661c281a61c0b9b028d0ad5",
};
const MAX_BYTES = 64 * 1024 * 1024;

const args = process.argv.slice(2);
let data;
let assets;
let build;
let e2e = false;
let clean = false;
const wanted = [];
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--data") data = resolve(args[++i]);
  else if (args[i] === "--split") wanted.push(args[++i]);
  else if (args[i] === "--e2e") e2e = true;
  else if (args[i] === "--clean") clean = true;
  else if (args[i] === "--assets") assets = resolve(args[++i]);
  else if (args[i] === "--build") build = args[++i];
  else throw new Error(`unknown argument ${args[i]}`);
}
if (!data || ((e2e || clean) && !assets)) throw new Error("usage: verifier-proof.mjs --data <s6-secrets2 folder> [--split S]... | --e2e --assets <dir> [--build B]");
const SPLITS = e2e ? ["validation"] : wanted.length > 0 ? wanted : ["training", "validation"];
for (const s of SPLITS) if (s !== "training" && s !== "validation") throw new Error(`refused: split "${s}" (only training and validation are allowed)`);

// ---------------------------------------------------------------- the split guard (gen/run-trainval.mjs)
const CREDDATA = join(data, "creddata");
const splits = JSON.parse(readFileSync(join(data, "splits.json"), "utf8"));
const allowed = new Map();
for (const split of ["training", "validation"]) for (const r of splits[split]) allowed.set(r.repo_id, split);
const testIds = new Set(splits.test.map((r) => (typeof r === "string" ? r : r.repo_id)));
if (allowed.size !== 116) throw new Error(`expected 116 training and validation repositories, got ${allowed.size}`);
for (const id of allowed.keys()) if (testIds.has(id)) throw new Error(`splits.json lists ${id} in the test too`);
function assertAllowed(repoId, split) {
  const is = allowed.get(repoId);
  if (is === undefined) throw new Error(`refused: RepoID ${repoId} is not a training or validation repository${testIds.has(repoId) ? " (it is a TEST repository)" : ""}`);
  if (split !== undefined && is !== split) throw new Error(`refused: RepoID ${repoId} belongs to ${is}, not ${split}`);
}
const repoOf = (path) => {
  const m = /^data\/([0-9a-f]{8})\//.exec(path);
  if (!m) throw new Error(`refused: ${path} is not a file of a CredData repository`);
  return m[1];
};
function* walk(dir, rel) {
  for (const e of readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
    if (e.isSymbolicLink()) continue;
    if (e.isDirectory()) yield* walk(join(dir, e.name), `${rel}/${e.name}`);
    else if (e.isFile()) yield `${rel}/${e.name}`;
  }
}
/** The files of a split, walked as the frozen runner walked them, checked against its list. */
function filesOf(split) {
  const files = [];
  for (const id of splits[split].map((r) => r.repo_id).sort()) {
    assertAllowed(id, split);
    for (const f of walk(join(CREDDATA, "data", id), `data/${id}`)) files.push(f);
  }
  for (const f of files) assertAllowed(repoOf(f), split);
  const frozen = readFileSync(join(data, "gen", `files-${split}.txt`), "utf8");
  if (frozen !== `${files.join("\n")}\n`) throw new Error(`${split}: the walk differs from the frozen gen/files-${split}.txt`);
  return files;
}

// The script's readText: missing, empty, too large or binary gives no text.
function readText(file) {
  const st = statSync(file, { throwIfNoEntry: false });
  if (st === undefined || !st.isFile() || st.size === 0 || st.size > MAX_BYTES) return undefined;
  const buf = readFileSync(file);
  if (buf.subarray(0, 8192).includes(0)) return undefined;
  return buf.toString("utf8");
}

// ---------------------------------------------------------------- the module under test, from its sources
nodeModule.registerHooks({
  resolve(spec, ctx, next) {
    try {
      return next(spec, ctx);
    } catch (err) {
      if (spec.startsWith(".") && spec.endsWith(".js")) return next(`${spec.slice(0, -3)}.ts`, ctx);
      throw err;
    }
  },
});
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const { candidateRecords } = await import(pathToFileURL(join(root, "src/verifier/generator.ts")).href);
const { engineCandidate, loadEngine } = await import(pathToFileURL(join(root, "src/verifier/verifier.ts")).href);

/** Every record of a split, in the frozen export's order. */
function* recordsOf(split, opts = {}) {
  for (const file of filesOf(split)) {
    const text = readText(join(CREDDATA, file));
    if (text === undefined) continue;
    for (const r of candidateRecords(text, { sourcePath: file, maxLine: 1000, ...opts })) {
      assertAllowed(repoOf(r.file), split);
      yield r;
    }
  }
}

async function* frozenLines(split) {
  for await (const line of createInterface({ input: createReadStream(join(data, "gen", `candidates-${split}.raw.jsonl`)), crlfDelay: Number.POSITIVE_INFINITY })) {
    if (line !== "") yield line;
  }
}

async function proveGenerator(split) {
  const began = performance.now();
  const hash = createHash("sha256");
  let n = 0;
  for (const r of recordsOf(split)) {
    hash.update(`${JSON.stringify(r)}\n`);
    n++;
  }
  const got = hash.digest("hex");
  const seconds = ((performance.now() - began) / 1000).toFixed(1);
  const same = got === FROZEN_SHA256[split];
  console.log(`${split}: ${n} records in ${seconds} s, sha256 ${got} — ${same ? "BYTE-IDENTICAL to the frozen export" : `DIFFERS from ${FROZEN_SHA256[split]}`}`);
  if (same) return true;
  // Where they differ: field by field, counts only.
  const mine = recordsOf(split);
  const differs = {};
  let compared = 0;
  let extra = 0;
  for await (const line of frozenLines(split)) {
    const next = mine.next();
    if (next.done) {
      extra++;
      continue;
    }
    compared++;
    const a = JSON.parse(line);
    const b = JSON.parse(JSON.stringify(next.value));
    for (const k of new Set([...Object.keys(a), ...Object.keys(b)])) if (JSON.stringify(a[k]) !== JSON.stringify(b[k])) differs[k] = (differs[k] ?? 0) + 1;
    if (Object.keys(a).join() !== Object.keys(b).join()) differs["(field order)"] = (differs["(field order)"] ?? 0) + 1;
  }
  let left = 0;
  for (let r = mine.next(); !r.done; r = mine.next()) left++;
  console.log(`${split}: ${compared} records compared in order; differing records per field ${JSON.stringify(differs)}; frozen has ${extra} more, this module ${left} more`);
  return false;
}

// CredData stores a file under the directories `get_file_scope()` wrote for its
// real path (data/<repo>/<scope…>/<id><ext>): the evaluation read the scope
// back from them (skycmd crates/sky-data/src/secrets2/mod.rs, stored_scope),
// and gave the model the record's own `ext`. A deployed host has a real path
// instead and passes it as `file`.
const WORD_IN_PATH = JSON.parse(readFileSync(join(CREDDATA, "word_in_path.json"), "utf8")).map((w) => w.replace(/^\/+|\/+$/g, ""));
function storedScope(file) {
  const parts = file.split("/");
  if (parts.length < 4 || parts[0] !== "data") throw new Error("not a CredData file under a scope directory");
  const dirs = parts.slice(2, -1);
  if (dirs.length === 1 && dirs[0] === "_") return [];
  const words = [];
  let at = 0;
  for (const dir of dirs) {
    while (at < WORD_IN_PATH.length && WORD_IN_PATH[at] !== dir) at++;
    if (at === WORD_IN_PATH.length) throw new Error("directories that are not a scope get_file_scope() writes");
    words.push(WORD_IN_PATH[at++]);
  }
  return words;
}

async function proveEndToEnd() {
  process.env.SECRETGATE_HOME = "/nonexistent"; // the assets come from --assets only
  const engine = loadEngine("f1", { dir: assets, ...(build ? { force: build } : {}) });
  const evalDir = join(data, "eval", "validation");
  const states = readFileSync(join(evalDir, "states", "creddata.jsonl"), "utf8").split("\n").filter(Boolean).map(JSON.parse);
  const dump = readFileSync(join(evalDir, "model", "creddata", "model-dump.jsonl"), "utf8")
    .split("\n")
    .filter(Boolean)
    .map(JSON.parse)
    .filter((d) => d.t === "noul");
  const flags = readFileSync(join(evalDir, "flags", "model.flags.jsonl"), "utf8").split("\n").filter(Boolean).map(JSON.parse);
  const run = JSON.parse(readFileSync(join(evalDir, "flags", "model.run.json"), "utf8"));
  if (states.length !== dump.length || states.length !== flags.length) throw new Error("the evaluation files do not line up");
  console.log(`engine ${engine.build}, tau_f1 ${engine.tau} (evaluation threshold ${run.threshold})`);

  let i = 0;
  let sameState = 0;
  let maxGap = 0;
  let maxGapToFlags = 0;
  const mineAccepted = new Set();
  const evalAccepted = new Set();
  const flagAccepted = new Set();
  const times = [];
  let nearest = Number.POSITIVE_INFINITY;
  for (const r of recordsOf("validation", { reported: false })) {
    if (states[i]?.id !== `cred:val:${i}` || flags[i]?.id !== i) throw new Error(`evaluation row ${i} is not candidate ${i}`);
    const c = { ...engineCandidate(r, undefined), scope: storedScope(r.file), ext: r.ext };
    if (engine.state(c) === states[i].state) sameState++;
    const t0 = performance.now();
    const p = engine.judge(c);
    times.push(performance.now() - t0);
    const ref = dump[i].probs[1];
    maxGap = Math.max(maxGap, Math.abs(p - ref));
    maxGapToFlags = Math.max(maxGapToFlags, Math.abs(p - flags[i].score));
    nearest = Math.min(nearest, Math.abs(p - engine.tau));
    if (p >= engine.tau) mineAccepted.add(i);
    if (ref >= run.threshold) evalAccepted.add(i);
    if (flags[i].score >= run.threshold) flagAccepted.add(i);
    i++;
  }
  if (i !== states.length) throw new Error(`${i} candidates, the evaluation has ${states.length}`);
  // The evaluation's accepted set is what its scorer read: the flags file
  // (P(real) written with 6 decimals) at `score >= threshold`. The dump keeps
  // the native engine's full-precision P, also compared.
  const diff = (a, b) => [...a].filter((x) => !b.has(x)).length;
  const onlyMine = diff(mineAccepted, flagAccepted);
  const onlyEval = diff(flagAccepted, mineAccepted);
  times.sort((a, b) => a - b);
  const q = (f) => times[Math.min(times.length - 1, Math.floor(f * times.length))].toFixed(2);
  console.log(`candidates ${i}; state identical to the evaluation's ${sameState}/${i}`);
  console.log(
    `accepted: this path ${mineAccepted.size}, the evaluation's scorer (flags file) ${flagAccepted.size}; only here ${onlyMine}, only there ${onlyEval}; ${onlyMine + onlyEval === 0 ? "SAME SET" : "SETS DIFFER"}`,
  );
  console.log(
    `against the native full-precision P of the dump (${evalAccepted.size} at P >= tau): only here ${diff(mineAccepted, evalAccepted)}, only there ${diff(evalAccepted, mineAccepted)}`,
  );
  console.log(`largest |P - P_eval| ${maxGap.toExponential(3)} (against the 6-decimal flags file ${maxGapToFlags.toExponential(3)}); nearest P to tau ${nearest.toExponential(3)}`);
  console.log(`judge time per candidate (ms): median ${q(0.5)}, p95 ${q(0.95)}`);
  return onlyMine + onlyEval === 0 && sameState === i;
}

// The evaluation of the clean corpus built each state with the file's path
// below its repository (its scope words and extension), though its generator
// ran with no source path.
async function proveClean() {
  process.env.SECRETGATE_HOME = "/nonexistent";
  const engine = loadEngine("f1", { dir: assets, ...(build ? { force: build } : {}) });
  const dir = join(data, "eval", "clean");
  const list = JSON.parse(readFileSync(join(data, "gen", "clean-corpus.json"), "utf8")).list;
  const states = readFileSync(join(dir, "states", "clean.jsonl"), "utf8").split("\n").filter(Boolean).map(JSON.parse);
  const flags = readFileSync(join(dir, "flags", "model.flags.jsonl"), "utf8").split("\n").filter(Boolean).map(JSON.parse);
  const run = JSON.parse(readFileSync(join(dir, "flags", "model.run.json"), "utf8"));
  let i = 0;
  const same = { path: 0, none: 0 };
  const accepted = { path: new Set(), none: new Set(), evaluation: new Set() };
  const files = { path: new Set(), none: new Set(), evaluation: new Set() };
  let gap = 0;
  for (const f of list) {
    const text = readFileSync(join(dir, "corpus", f.repository, f.path), "utf8");
    for (const r of candidateRecords(text, { reported: false })) {
      const withPath = engineCandidate(r, f.path);
      const without = engineCandidate(r, undefined);
      if (engine.state(withPath) === states[i].state) same.path++;
      if (engine.state(without) === states[i].state) same.none++;
      const p = engine.judge(withPath);
      gap = Math.max(gap, Math.abs(p - flags[i].score));
      for (const [k, yes] of [
        ["path", p >= engine.tau],
        ["none", engine.judge(without) >= engine.tau],
        ["evaluation", flags[i].score >= run.threshold],
      ])
        if (yes) {
          accepted[k].add(i);
          files[k].add(f.path);
        }
      i++;
    }
  }
  const diff = (a, b) => [...a].filter((x) => !b.has(x)).length;
  console.log(`clean corpus: ${list.length} files, ${i} candidates (evaluation: ${states.length}); state identical with the path ${same.path}/${i}, without a path ${same.none}/${i}`);
  console.log(
    `accepted with the path ${accepted.path.size} in ${files.path.size} files, the evaluation ${accepted.evaluation.size} in ${files.evaluation.size}; only here ${diff(accepted.path, accepted.evaluation)}, only there ${diff(accepted.evaluation, accepted.path)}; largest |P - P_flags| ${gap.toExponential(3)}`,
  );
  console.log(`accepted without a path ${accepted.none.size} in ${files.none.size} files`);
  return same.path === i && i === states.length && diff(accepted.path, accepted.evaluation) + diff(accepted.evaluation, accepted.path) === 0;
}

let ok = true;
if (clean) ok = await proveClean();
else if (e2e) ok = await proveEndToEnd();
else for (const split of SPLITS) ok = (await proveGenerator(split)) && ok;
process.exitCode = ok ? 0 : 1;
