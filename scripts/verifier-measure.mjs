#!/usr/bin/env node
// What the verifier option costs and adds, measured the way a hook pays it:
// one fresh process of the built bundle per file, the file's text as the
// output of a tool call (PostToolUse), once with the verifier off and once on.
// Dev-only: not in the bundle. Needs the four pinned data files.
//
//   nice -n 19 node scripts/verifier-measure.mjs --assets <dir> --clean-corpus <clean-corpus.json> --base <dir>
//   nice -n 19 node scripts/verifier-measure.mjs --assets <dir> --tree <dir> [--read]
//
// --clean-corpus reads the list of the census corpus of docs/model-comparison.md
// as the s6-secrets v2 data froze it (`list`: repository and path, below
// --base); --tree walks a directory. Each file is handed over as the stdout
// of a Bash call (no path, as the census reads files), or with --read as a
// Read of the file (its path below the repository goes to the model).
//
// Per file it records the verifier's own line (SECRETGATE_DEBUG=verifier:
// counts and times, never a value; the child process's time from spawn to
// answer, and whether the hard bound killed it) and the wall time of both processes, and
// checks that the verifier only ADDED redactions: the output with it on, with
// every verifier placeholder put back, must be the output with it off. It
// prints aggregates only: no value, no line of any file.
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { copyFileSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const bundle = join(root, "scripts", "secretgate.mjs");
const args = process.argv.slice(2);
const opt = {};
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === "--read") opt.read = true;
  else if (["--assets", "--clean-corpus", "--base", "--tree"].includes(a)) opt[a.slice(2)] = resolve(args[++i]);
  else throw new Error(`unknown argument ${a}`);
}
if (!opt.assets || !(opt["clean-corpus"] || opt.tree)) throw new Error("usage: verifier-measure.mjs --assets <dir> (--clean-corpus <json> --base <dir> | --tree <dir>) [--read]");

// One vault salt for both runs: the same value gets the same placeholder in both.
const SALT = randomBytes(32).toString("hex");
const FILES = ["sky_web_bg.wasm", "sky_web_relaxed_bg.wasm", "s6-secrets-verify-pico.gguf", "dictionary.txt"];
const ASSET_SUBDIR = join("verifier", "s6-secrets-verify-pico-9d44c27848bc");
function home(on) {
  const h = mkdtempSync(join(tmpdir(), `secretgate-measure-${on ? "on" : "off"}-`));
  writeFileSync(join(h, "salt"), SALT, { mode: 0o600 });
  if (on) {
    mkdirSync(join(h, ASSET_SUBDIR), { recursive: true });
    for (const f of FILES) copyFileSync(join(opt.assets, f), join(h, ASSET_SUBDIR, f));
    writeFileSync(join(h, "config.json"), JSON.stringify({ verifier: { enabled: true, threshold: "f1" } }));
  }
  return h;
}

function* walk(dir) {
  for (const e of readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
    if (e.isSymbolicLink()) continue;
    const full = join(dir, e.name);
    if (e.isDirectory()) yield* walk(full);
    else if (e.isFile()) yield full;
  }
}
// [file, the root of its repository]
const files = opt.tree
  ? [...walk(opt.tree)].map((f) => [f, opt.tree])
  : JSON.parse(readFileSync(opt["clean-corpus"], "utf8")).list.map((f) => [join(opt.base, f.repository, f.path), join(opt.base, f.repository)]);

function event(file, repo, text) {
  if (!opt.read) return { session_id: "m", cwd: tmpdir(), tool_name: "Bash", tool_input: { command: "cat" }, tool_response: { stdout: text, stderr: "", interrupted: false, isImage: false } };
  // The repository's root as the working directory: the path below it goes to the model.
  return { session_id: "m", cwd: repo, tool_name: "Read", tool_input: { file_path: file }, tool_response: { type: "text", file: { filePath: file, content: text, numLines: 1, startLine: 1, totalLines: 1 } } };
}

function hook(h, input) {
  const env = { ...process.env, SECRETGATE_HOME: h, SECRETGATE_DEBUG: "verifier" };
  delete env.CLAUDE_PROJECT_DIR;
  const t0 = process.hrtime.bigint();
  const r = spawnSync(process.execPath, [bundle, "hook", "claude-code", "post-tool-use"], { input, env, encoding: "utf8", maxBuffer: 256 * 1024 * 1024 });
  return { ms: Number(process.hrtime.bigint() - t0) / 1e6, ...r };
}
const outputOf = (r) => (r.stdout.trim() === "" ? undefined : JSON.parse(r.stdout).hookSpecificOutput?.updatedToolOutput);

const homes = { off: home(false), on: home(true) };
const quantile = (xs, q) => {
  const s = [...xs].sort((a, b) => a - b);
  return s.length === 0 ? Number.NaN : s[Math.min(s.length - 1, Math.floor(q * s.length))];
};
const stats = {
  files: 0,
  skipped: 0,
  failures: { off: 0, on: 0 },
  withCandidates: 0,
  judgedFiles: 0,
  redactedFiles: 0,
  accepted: 0,
  acceptedByRule: {},
  judged: 0,
  candidates: 0,
  covered: 0,
  unjudged: 0,
  budgetFiles: 0,
  hardBoundFiles: 0,
  spread: 0,
  spreadFiles: 0,
  childFailures: {},
  stringsSkipped: {},
  builds: {},
  rulesChanged: 0,
};
const verifierMs = [];
const childMs = [];
const verifierMsLoaded = [];
const loadMs = [];
const wallOff = [];
// The five files the verifier slowed most: their paths and times, no content.
const top = [];
const wallOn = [];
const began = performance.now();
for (const [file, repo] of files) {
  const st = statSync(file, { throwIfNoEntry: false });
  if (!st?.isFile() || st.size === 0 || st.size > 2 * 1024 * 1024) {
    stats.skipped++;
    continue;
  }
  const buf = readFileSync(file);
  if (buf.subarray(0, 8192).includes(0)) {
    stats.skipped++;
    continue;
  }
  stats.files++;
  const input = JSON.stringify(event(file, repo, buf.toString("utf8")));
  const off = hook(homes.off, input);
  const on = hook(homes.on, input);
  wallOff.push(off.ms);
  wallOn.push(on.ms);
  top.push({ file: opt.tree ? relative(opt.tree, file) : relative(opt.base, file), off: Math.round(off.ms), on: Math.round(on.ms), child: Number(/(?:answered in|after) (\d+) ms/.exec(on.stderr)?.[1] ?? 0) });
  top.sort((a, b) => b.on - b.off - (a.on - a.off));
  top.length = Math.min(top.length, 5);
  if (off.status !== 0) stats.failures.off++;
  if (on.status !== 0) stats.failures.on++;
  const spreadLine = /spread to (\d+) other place/.exec(on.stderr);
  if (spreadLine) {
    stats.spread += Number(spreadLine[1]);
    stats.spreadFiles++;
  }
  const line = on.stderr.split("\n").find((l) => l.startsWith("secretgate verifier: "));
  if (line === undefined) continue;
  // The child's time, spawn to answer (or to its kill at the hard bound).
  const child = /(?:answered in|after) (\d+) ms/.exec(line);
  if (child) childMs.push(Number(child[1]));
  const dropped = /the child (.+?) after \d+ ms/.exec(line);
  if (dropped) {
    stats.childFailures[dropped[1]] = (stats.childFailures[dropped[1]] ?? 0) + 1;
    if (dropped[1] === "hard bound") stats.hardBoundFiles++;
  }
  const n = (re) => Number(re.exec(line)?.[1] ?? 0);
  const cands = n(/(\d+) candidate\(s\)/);
  const judged = n(/(\d+) judged/);
  const accepted = n(/(\d+) accepted;/);
  stats.candidates += cands;
  stats.covered += n(/(\d+) left to a rule/);
  stats.judged += judged;
  stats.accepted += accepted;
  stats.unjudged += n(/(\d+) NOT judged/);
  if (/NOT judged \(budget|NOT judged \(candidate cap/.test(line)) stats.budgetFiles++;
  if (cands > 0) stats.withCandidates++;
  if (judged > 0) stats.judgedFiles++;
  if (accepted > 0) stats.redactedFiles++;
  for (const m of line.matchAll(/accepted line \d+ \(([^,]+), p/g)) stats.acceptedByRule[m[1]] = (stats.acceptedByRule[m[1]] ?? 0) + 1;
  for (const m of line.matchAll(/(\d+) (too long|generic-keyword bound|generator deadline)/g)) stats.stringsSkipped[m[2]] = (stats.stringsSkipped[m[2]] ?? 0) + Number(m[1]);
  const build = /engine (\S+), loaded in ([\d.]+) ms/.exec(line);
  const total = n(/verifier total ([\d.]+) ms/);
  verifierMs.push(total);
  if (build) {
    stats.builds[build[1]] = (stats.builds[build[1]] ?? 0) + 1;
    loadMs.push(Number(build[2]));
    verifierMsLoaded.push(total);
  }
  // The verifier may only add: put back every placeholder the output without
  // it does not have, and the output must be the rules' output.
  const offText = JSON.stringify(outputOf(off) ?? JSON.parse(input).tool_response);
  let onText = JSON.stringify(outputOf(on) ?? JSON.parse(input).tool_response);
  if (onText !== offText) {
    const vault = JSON.parse(readFileSync(join(homes.on, "vault.json"), "utf8")).entries;
    for (const placeholder of new Set(onText.match(/SECRETGATE_[0-9a-f]{12,16}/g) ?? []))
      if (!offText.includes(placeholder) && vault[placeholder]) onText = onText.split(placeholder).join(JSON.stringify(vault[placeholder].secret).slice(1, -1));
    if (onText !== offText) stats.rulesChanged++;
  }
}
for (const h of Object.values(homes)) rmSync(h, { recursive: true, force: true });
const ms = (xs) => ({ median: Number(quantile(xs, 0.5).toFixed(2)), p95: Number(quantile(xs, 0.95).toFixed(2)), max: Number(quantile(xs, 1).toFixed(2)) });
const added = wallOn.map((x, i) => x - wallOff[i]);
console.log(
  JSON.stringify(
    {
      corpus: opt.tree ? relative(root, opt.tree) || "." : "census (clean-corpus.json)",
      reading: opt.read ? "Read, with the path below the repository" : "Bash stdout, no path",
      node: process.version,
      ...stats,
      childMsPerFile: ms(childMs),
      verifierMsPerFile: ms(verifierMs),
      verifierMsPerFileWhenItLoadedTheEngine: { files: verifierMsLoaded.length, ...ms(verifierMsLoaded) },
      engineLoadMs: ms(loadMs),
      hookWallMs: { off: ms(wallOff), on: ms(wallOn), addedPerFile: ms(added) },
      slowest: top,
      seconds: Number(((performance.now() - began) / 1000).toFixed(0)),
    },
    null,
    2,
  ),
);
