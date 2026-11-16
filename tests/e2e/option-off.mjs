#!/usr/bin/env node
// With the verifier option OFF, nothing may change. This runs the bundles of a
// base ref (default origin/main, read from git) and of the working tree on the
// same recorded inputs, each in a fresh home with the same vault salt, and
// compares everything they produce:
//   - every hook event every installer wires: Claude Code (UserPromptSubmit,
//     PreToolUse, PostToolUse, PostToolBatch) and Codex (UserPromptSubmit,
//     PreToolUse, PostToolUse), as one sequence per host (a placeholder made
//     by one event is restored by a later one; a pause set by one applies to
//     the next);
//   - the OpenCode plugin's entry points (prompt, context, execute.before,
//     execute.after), from each plugin bundle, on the same events;
//   - the CLI commands that print: scan (a tree, stdin, --json), pipe, vault
//     list, status, --help;
//   - stdout, stderr, exit code, and every file written under the home and the
//     project (vault timestamps aside).
// It prints each difference, and exits 1 if there is one it was not told to
// expect (EXPECTED below: the verifier's own new lines).
//
//   node tests/e2e/option-off.mjs [--base <git ref>]
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = resolve(fileURLToPath(new URL("../..", import.meta.url)));
const baseRef = process.argv.includes("--base") ? process.argv[process.argv.indexOf("--base") + 1] : "origin/main";
const scratch = realpathSync(mkdtempSync(join(tmpdir(), "secretgate-option-off-")));

// Fake values, assembled at run time.
const GH = "ghp_" + ["aB3dE6", "gH9jK2", "mN5pQ8", "sT1vW4", "yZ7bC0", "dF6hJ9"].join("");
const PW = ["Qm7", "xR2", "pL9", "vN4", "kT8"].join("");
const SALT = "5".repeat(64);

// The two programs: the base ref's committed bundles, and the working tree's.
const sides = {};
for (const [name, from] of [
  ["base", (f) => execFileSync("git", ["-C", root, "show", `${baseRef}:scripts/${f}`])],
  ["branch", (f) => readFileSync(join(root, "scripts", f))],
]) {
  const dir = join(scratch, `bundle-${name}`);
  mkdirSync(dir, { recursive: true });
  for (const f of ["secretgate.mjs", "secretgate-opencode.mjs"]) writeFileSync(join(dir, f), from(f));
  sides[name] = { cli: join(dir, "secretgate.mjs"), plugin: join(dir, "secretgate-opencode.mjs") };
}

// A home and a project per side and per scenario.
function world(side, scenario) {
  const base = join(scratch, `${scenario}-${side}`);
  const home = join(base, "home");
  const state = join(home, ".secretgate");
  const project = join(base, "project");
  for (const d of [state, join(project, ".git"), join(project, "tests"), join(project, "src")]) mkdirSync(d, { recursive: true });
  writeFileSync(join(state, "salt"), SALT, { mode: 0o600 });
  writeFileSync(join(project, ".env"), `TOKEN=${GH}\n`);
  writeFileSync(join(project, "src", "ci.txt"), `CI_TOKEN=${GH}\nDB_PASS=${PW}\n`);
  writeFileSync(join(project, "tests", "fixture.ts"), `export const t = "${GH}";\n`);
  return { base, home, state, project };
}
const envOf = (w) => {
  const env = { ...process.env, HOME: w.home, SECRETGATE_HOME: w.state, XDG_CONFIG_HOME: join(w.home, ".config") };
  for (const k of ["CLAUDE_PROJECT_DIR", "CLAUDE_CODE_SESSION_ID", "SECRETGATE_DISABLE", "SECRETGATE_DEBUG", "OPENCODE_CONFIG_DIR", "CODEX_HOME"])
    delete env[k];
  return env;
};

// What a run leaves behind: every file under the world, the vault's
// timestamps aside, the world's own paths written as <W>.
function snapshot(w) {
  const out = {};
  const walk = (dir) => {
    for (const e of readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
      const full = join(dir, e.name);
      if (e.isDirectory()) walk(full);
      else if (e.isFile()) {
        let text = readFileSync(full, "utf8").replaceAll(w.base, "<W>");
        if (e.name === "vault.json") text = text.replace(/"firstSeen": "[^"]*"/g, '"firstSeen": "<T>"');
        if (e.name.endsWith(".json") && /disabled|sessions/.test(e.name))
          text = text.replace(/"(?:until|at|since|seen|lastSeen|updated)": "[^"]*"/g, '"$1": "<T>"');
        out[relative(w.base, full)] = `${(statSync(full).mode & 0o777).toString(8)} ${text}`;
      }
    }
  };
  walk(w.base);
  return out;
}
const norm = (w, s) => s.replaceAll(w.base, "<W>").replace(/\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z/g, "<T>");

// ---------------------------------------------------------------- the inputs
const ev = (w, o) => JSON.stringify({ session_id: "sess-1", cwd: w.project, ...o });
const bashOut = (stdout) => ({ stdout, stderr: "", interrupted: false, isImage: false });
const CLAUDE = (w) => [
  ["user-prompt-submit", ev(w, { prompt: "refactor the parser" })],
  ["user-prompt-submit", ev(w, { prompt: `use this key ${GH} for the deploy` })],
  ["user-prompt-submit", ev(w, { prompt: `[allow-secret] ${GH}` })],
  ["user-prompt-submit", ev(w, { prompt: "look at @.env please" })],
  ["user-prompt-submit", ev(w, { prompt: `DB_PASS=${PW}` })],
  ["pre-tool-use", ev(w, { tool_name: "Read", tool_input: { file_path: join(w.project, ".env") } })],
  ["pre-tool-use", ev(w, { tool_name: "Read", tool_input: { file_path: join(w.project, "src", "ci.txt") } })],
  ["pre-tool-use", ev(w, { tool_name: "Bash", tool_input: { command: "cat .env" } })],
  ["pre-tool-use", ev(w, { tool_name: "Bash", tool_input: { command: "secretgate disable --forever" } })],
  ["post-tool-use", ev(w, { tool_name: "Bash", tool_input: { command: "env" }, tool_response: bashOut(`HOME=/x\nGITHUB_TOKEN=${GH}\nDB_PASS=${PW}\n`) })],
  ["post-tool-use", ev(w, { tool_name: "Bash", tool_input: { command: "ls" }, tool_response: bashOut("a b c\n") })],
  [
    "post-tool-use",
    ev(w, {
      tool_name: "Read",
      tool_input: { file_path: join(w.project, "src", "ci.txt") },
      tool_response: {
        type: "text",
        file: { filePath: join(w.project, "src", "ci.txt"), content: `CI_TOKEN=${GH}\nDB_PASS=${PW}\n`, numLines: 2, startLine: 1, totalLines: 2 },
      },
    }),
  ],
  ["post-tool-use", ev(w, { tool_name: "mcp__x__y", tool_input: {}, tool_response: [{ type: "text", text: `token: ${GH}` }] })],
  ["post-tool-use", ev(w, { tool_name: "Bash", tool_input: { command: "big" }, tool_response: bashOut(`${"x".repeat(3 * 1024 * 1024)}`) })],
  ["post-tool-use", "{not json"],
  ["post-tool-batch", ev(w, { tool_calls: [{ tool_name: "Bash", tool_input: {}, tool_use_id: "t1", tool_response: "a b c" }] })],
  [
    "post-tool-batch",
    ev(w, { session_id: "sess-2", tool_calls: [{ tool_name: "Bash", tool_input: {}, tool_use_id: "t2", tool_response: `Exit code 1\nDB_PASS=${PW}` }] }),
  ],
  [
    "post-tool-batch",
    ev(w, { session_id: "sess-3", tool_calls: [{ tool_name: "Bash", tool_input: {}, tool_use_id: "t3", tool_response: `Exit code 1\nT=${GH}` }] }),
  ],
  // A placeholder made above, written back (the vault is the same: same salt).
  ["pre-tool-use", "PLACEHOLDER_WRITE"],
  ["user-prompt-submit", ev(w, { session_id: "sess-4", prompt: "/secretgate off" })],
  ["post-tool-use", ev(w, { session_id: "sess-4", tool_name: "Bash", tool_input: { command: "env" }, tool_response: bashOut(`GITHUB_TOKEN=${GH}\n`) })],
  ["user-prompt-submit", ev(w, { session_id: "sess-4", prompt: "/secretgate on" })],
];

function hook(side, w, agent, event, input) {
  const r = spawnSync(process.execPath, [sides[side].cli, "hook", agent, event], {
    input,
    cwd: w.project,
    env: envOf(w),
    encoding: "utf8",
    maxBuffer: 1 << 28,
  });
  return { status: r.status, stdout: norm(w, r.stdout), stderr: norm(w, r.stderr) };
}

function hostSequence(side, agent) {
  const w = world(side, agent);
  const steps = [];
  for (const [event, input0] of CLAUDE(w)) {
    let input = input0;
    if (input === "PLACEHOLDER_WRITE") {
      const vault = JSON.parse(readFileSync(join(w.state, "vault.json"), "utf8"));
      const placeholder = Object.keys(vault.entries)[0];
      input = ev(w, {
        tool_name: agent === "codex" ? "apply_patch" : "Write",
        tool_input: { file_path: join(w.project, "out.txt"), content: `T=${placeholder}\n` },
      });
    }
    steps.push({ event, ...hook(side, w, agent, event, input) });
  }
  return { steps, files: snapshot(w) };
}

// The OpenCode plugin, from its bundle, driven through a stub context.
async function opencode(side) {
  const w = world(side, "opencode");
  process.env.SECRETGATE_HOME = w.state;
  const mod = await import(`${pathToFileURL(sides[side].plugin).href}?${side}`);
  const hooks = {};
  const register = async (name, cb) => {
    hooks[name] = cb;
  };
  await mod.default.setup({ location: { directory: w.project }, session: { hook: register, get: async () => ({}) }, tool: { hook: register } });
  const steps = [];
  const step = async (name, event) => {
    let error;
    try {
      await hooks[name](event);
    } catch (err) {
      error = String(err?.message ?? err);
    }
    steps.push({ name, event: norm(w, JSON.stringify(event)), error: error && norm(w, error) });
  };
  await step("prompt", { sessionID: "oc1", prompt: { text: `deploy with ${GH}`, files: [] } });
  await step("prompt", { sessionID: "oc1", prompt: { text: `DB_PASS=${PW}`, files: [] } });
  await step("execute.before", { tool: "read", sessionID: "oc1", input: { filePath: join(w.project, ".env") } });
  await step("execute.before", { tool: "shell", sessionID: "oc1", input: { command: "ls" } });
  await step("execute.after", {
    tool: "shell",
    sessionID: "oc1",
    status: "completed",
    input: { command: "env" },
    result: { output: { exit: 0, output: `T=${GH}\nDB_PASS=${PW}` }, content: [{ type: "text", text: `T=${GH}\nDB_PASS=${PW}` }], metadata: {} },
  });
  await step("execute.after", { tool: "shell", sessionID: "oc1", status: "error", input: {}, result: { content: [{ type: "text", text: `T=${GH}` }] } });
  await step("context", {
    sessionID: "oc1",
    messages: [
      { role: "user", content: [{ type: "text", text: `here ${GH}` }] },
      { role: "assistant", content: [{ type: "tool-result", output: `DB_PASS=${PW}` }] },
    ],
  });
  delete process.env.SECRETGATE_HOME;
  return { steps, files: snapshot(w) };
}

function cli(side) {
  const w = world(side, "cli");
  const run = (args, input) => {
    const r = spawnSync(process.execPath, [sides[side].cli, ...args], { input, cwd: w.project, env: envOf(w), encoding: "utf8", maxBuffer: 1 << 26 });
    return { args: args.join(" "), status: r.status, stdout: norm(w, r.stdout), stderr: norm(w, r.stderr) };
  };
  const steps = [
    run(["scan", "."]),
    run(["scan", ".", "--json", "--no-gitleaks"]),
    run(["scan", "-", "--no-gitleaks"], `T=${GH}\nDB_PASS=${PW}\n`),
    run(["pipe"], `T=${GH}\nDB_PASS=${PW}\n`),
    run(["vault", "list"]),
    run(["status"]),
    run(["--help"]),
    run(["verifier"]),
  ];
  return { steps, files: snapshot(w) };
}

// ---------------------------------------------------------------- compare
// Differences that are the option's own, and nothing else: the new `status`
// line, the new command in --help, the new command itself, and the new
// guarded commands (none of which the base knows).
const EXPECTED = [
  { where: /^cli status stdout$/, line: /^verifier {2}off \(experimental, opt-in/ },
  { where: /^cli --help stdout$/, line: /^ {2}verifier {4}The experimental, opt-in ML verifier/ },
];

const diffs = [];
function compareText(where, a, b) {
  if (a === b) return;
  const la = a.split("\n");
  const lb = b.split("\n");
  const onlyA = la.filter((l) => !lb.includes(l));
  const onlyB = lb.filter((l) => !la.includes(l));
  const expected = (l) => EXPECTED.some((e) => e.where.test(where) && e.line.test(l));
  // The `verifier` command is new: the base answers it as an unknown command.
  const newCommand = /^cli verifier /.test(where);
  const unexpected = newCommand ? [] : [...onlyA.map((l) => `- ${l}`), ...onlyB.filter((l) => !expected(l)).map((l) => `+ ${l}`)];
  const intended = onlyB.filter(expected);
  diffs.push({
    where,
    unexpected,
    intended: newCommand ? [`(a command the base does not have: ${onlyB.length} line(s))`] : intended,
    order: !newCommand && onlyA.length + onlyB.length === 0,
  });
}
function compare(name, a, b) {
  a.steps.forEach((s, i) => {
    const t = b.steps[i];
    const label = s.args ?? s.name ?? `${i} ${s.event}`;
    for (const k of Object.keys(s)) if (k !== "args" && k !== "name") compareText(`${name} ${label} ${k}`, String(s[k] ?? ""), String(t[k] ?? ""));
  });
  for (const f of new Set([...Object.keys(a.files), ...Object.keys(b.files)]))
    compareText(`${name} file ${f}`, a.files[f] ?? "<absent>", b.files[f] ?? "<absent>");
}

const results = {};
for (const side of ["base", "branch"])
  results[side] = { "claude-code": hostSequence(side, "claude-code"), codex: hostSequence(side, "codex"), opencode: await opencode(side), cli: cli(side) };
let steps = 0;
for (const name of ["claude-code", "codex", "opencode", "cli"]) {
  steps += results.base[name].steps.length;
  compare(name, results.base[name], results.branch[name]);
}
rmSync(scratch, { recursive: true, force: true });

const bad = diffs.filter((d) => d.unexpected.length > 0 || d.order);
for (const d of diffs) {
  console.log(`${d.unexpected.length > 0 || d.order ? "DIFF" : "intended"}  ${d.where}`);
  for (const l of d.unexpected) console.log(`        ${l.replaceAll(GH, "<GH>").replaceAll(PW, "<PW>").slice(0, 300)}`);
  for (const l of d.intended) console.log(`        (intended) + ${l.slice(0, 160)}`);
}
const answered = ["claude-code", "codex", "opencode", "cli"]
  .flatMap((n) => results.base[n].steps)
  .filter((s) => (s.stdout ?? s.event ?? "").includes("SECRETGATE_") || /"decision"|permissionDecision|continue|withheld/.test(s.stdout ?? "")).length;
console.log(`option-off: ${answered} of the base's steps redact, block, deny, ask or stop`);
console.log(
  `option-off: ${steps} steps compared (Claude Code, Codex, OpenCode, CLI) against ${baseRef}: ${bad.length} unexpected difference(s), ${diffs.length - bad.length} intended`,
);
process.exitCode = bad.length > 0 ? 1 : 0;
