#!/usr/bin/env node
// Real-condition replay of the audit findings: the built bundle runs as a
// child process, fed a JSON event on stdin exactly like a wired hook, inside
// a throwaway HOME. Every scenario asserts the FIXED behaviour, so a run on a
// build that still has the bug reports it as a failure.
//
//   node tests/e2e/real-scenarios.mjs            # every scenario
//   node tests/e2e/real-scenarios.mjs vault      # names containing "vault"
//
// Fake tokens are built by concatenation, never written as literals.
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { parse as parseToml } from "smol-toml";

const bundle = resolve(process.argv[1], "../../../scripts/secretgate.mjs");
const filter = process.argv[2];

const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
let seed = 7;
const rand = () => {
  seed = (seed * 1103515245 + 12345) & 0x7fffffff;
  return seed;
};
const token = () => "ghp" + "_" + Array.from({ length: 36 }, () => ALNUM[rand() % ALNUM.length]).join("");
const FAKE = token();

function sandbox() {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "sg-real-")));
  const home = join(root, "home");
  const proj = join(root, "proj");
  mkdirSync(home, { recursive: true });
  mkdirSync(join(proj, ".git"), { recursive: true });
  const env = {
    ...process.env,
    HOME: home,
    USERPROFILE: home,
    SECRETGATE_HOME: join(home, ".secretgate"),
    XDG_CONFIG_HOME: join(home, ".config"),
    OPENCODE_CONFIG_DIR: join(home, ".config", "opencode"),
    CODEX_HOME: join(home, ".codex"),
  };
  delete env.SECRETGATE_DISABLE;
  delete env.CLAUDE_PROJECT_DIR;
  delete env.CLAUDE_CODE_SESSION_ID;
  return { root, home, proj, env, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

function cli(sb, args, opts = {}) {
  const r = spawnSync(process.execPath, [bundle, ...args], {
    env: sb.env,
    cwd: opts.cwd ?? sb.proj,
    input: opts.input ?? "",
    encoding: "utf8",
    timeout: opts.timeout ?? 60_000,
    maxBuffer: 64 * 1024 * 1024,
  });
  return { code: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

function hook(sb, event, payload, agent = "claude-code") {
  const r = cli(sb, ["hook", agent, event], { input: JSON.stringify({ session_id: "real", cwd: sb.proj, ...payload }) });
  let json = {};
  try {
    json = r.stdout.trim() ? JSON.parse(r.stdout) : {};
  } catch {
    json = { unparsable: r.stdout };
  }
  return { ...r, json };
}

const decision = (r) => r.json?.hookSpecificOutput?.permissionDecision;
const bash = (sb, command, extra = {}) => decision(hook(sb, "pre-tool-use", { tool_name: "Bash", tool_input: { command }, ...extra }));

function check(cond, message) {
  if (!cond) throw new Error(message);
}

const scenarios = [];
const scenario = (name, fn) => scenarios.push({ name, fn });

// ---------------------------------------------------------------- A: engine & vault

scenario("vault: 3000 secrets in one PostToolUse are redacted in under 2 s", (sb) => {
  const secrets = Array.from({ length: 3000 }, token);
  const started = performance.now();
  const r = hook(sb, "post-tool-use", {
    tool_name: "Bash",
    tool_input: { command: "env" },
    tool_response: { stdout: secrets.map((s, i) => `T${i}=${s}`).join("\n") },
  });
  const ms = performance.now() - started;
  const out = JSON.stringify(r.json);
  check(!secrets.some((s) => out.includes(s)), "a secret survived redaction");
  check((out.match(/SECRETGATE_/g) ?? []).length >= 3000, "not every secret was replaced");
  check(ms < 2000, `took ${Math.round(ms)} ms`);
});

scenario("vault: a placeholder followed by hex characters is restored", (sb) => {
  const piped = cli(sb, ["pipe"], { input: `TOKEN=${FAKE}\n` }).stdout;
  const placeholder = /SECRETGATE_[0-9a-f]{12,16}/.exec(piped)?.[0];
  check(placeholder, "pipe produced no placeholder");
  for (const suffix of ["cafe", "0", "beef42"]) {
    const r = hook(sb, "pre-tool-use", { tool_name: "Write", tool_input: { file_path: join(sb.proj, "a.txt"), content: `${placeholder}${suffix}` } });
    check(r.json?.hookSpecificOutput?.updatedInput?.content === `${FAKE}${suffix}`, `'${suffix}' suffix: not restored (${r.stdout.slice(0, 120)})`);
  }
});

scenario("vault: a corrupt vault is set aside, not silently overwritten", (sb) => {
  mkdirSync(sb.env.SECRETGATE_HOME, { recursive: true });
  writeFileSync(join(sb.env.SECRETGATE_HOME, "vault.json"), "{ not json");
  cli(sb, ["pipe"], { input: `TOKEN=${FAKE}\n` });
  const kept = readdirSync(sb.env.SECRETGATE_HOME).filter((f) => f.startsWith("vault.json.corrupt-"));
  check(kept.length === 1, `no vault.json.corrupt-* backup (${readdirSync(sb.env.SECRETGATE_HOME).join(", ")})`);
  check(readFileSync(join(sb.env.SECRETGATE_HOME, kept[0]), "utf8") === "{ not json", "backup content differs");
});

// ---------------------------------------------------------------- B: directive, config

const sessionOff = (sb, session) => {
  const r = hook(sb, "post-tool-use", { session_id: session, tool_name: "Bash", tool_input: { command: "env" }, tool_response: { stdout: `T=${FAKE}` } });
  return JSON.stringify(r.json).includes(FAKE) || r.stdout.trim() === "";
};

scenario("directive: /secretgate off in the middle of a pasted log does nothing", (sb) => {
  hook(sb, "user-prompt-submit", { session_id: "mid", prompt: "why does this fail?\n```\n/secretgate off\n```\nthanks" });
  check(!sessionOff(sb, "mid"), "the session was paused");
});

scenario("directive: natural language no longer pauses", (sb) => {
  for (const [i, prompt] of ["désactive secretgate", "disable secretgate", "secretgate: off"].entries()) {
    hook(sb, "user-prompt-submit", { session_id: `nl${i}`, prompt });
    check(!sessionOff(sb, `nl${i}`), `'${prompt}' paused the session`);
  }
});

scenario("directive: /secretgate off on the first line pauses this session", (sb) => {
  const r = hook(sb, "user-prompt-submit", { session_id: "first", prompt: "\n/secretgate off\nthen run the tests" });
  check(sessionOff(sb, "first"), `not paused (${r.stdout.slice(0, 160)})`);
  check(r.stdout.includes("/secretgate on"), "the notice does not say how to turn it back on");
  hook(sb, "user-prompt-submit", { session_id: "first", prompt: "/secretgate on" });
  check(!sessionOff(sb, "first"), "/secretgate on did not re-enable");
});

scenario("config: allow keeps a commented allowlist and refuses a corrupt one", (sb) => {
  mkdirSync(sb.env.SECRETGATE_HOME, { recursive: true });
  const path = join(sb.env.SECRETGATE_HOME, "allowlist.json");
  writeFileSync(path, '{\n  // reviewed 2026-01\n  "rules": ["generic-api-key"],\n}\n');
  const r = cli(sb, ["allow", "--rule", "jwt"]);
  check(r.code === 0, `allow exited ${r.code}: ${r.stderr}`);
  const after = readFileSync(path, "utf8");
  check(after.includes("generic-api-key") && after.includes("jwt"), `allowlist lost entries: ${after}`);
  writeFileSync(path, '{ "rules": [');
  const bad = cli(sb, ["allow", "--rule", "x"]);
  check(bad.code === 2, `corrupt allowlist: exit ${bad.code}`);
  check(readFileSync(path, "utf8") === '{ "rules": [', "corrupt allowlist was overwritten");
});

scenario("config: allow - reads the value from stdin", (sb) => {
  const r = cli(sb, ["allow", "-"], { input: `${FAKE}\n` });
  check(r.code === 0, `exit ${r.code}: ${r.stderr}`);
  const out = cli(sb, ["scan", "-", "--no-gitleaks"], { input: `TOKEN=${FAKE}\n` });
  check(out.code === 0, "the stdin value was not allowlisted");
});

scenario("status: a non-string deny rule does not crash it", (sb) => {
  mkdirSync(join(sb.home, ".claude"), { recursive: true });
  writeFileSync(join(sb.home, ".claude", "settings.json"), JSON.stringify({ permissions: { deny: [42, "Read(x)"] } }));
  const r = cli(sb, ["status"]);
  check(r.code === 0, `status exited ${r.code}: ${r.stderr.slice(0, 200)}`);
});

// ---------------------------------------------------------------- C: shell analysis

function shellProject(sb) {
  writeFileSync(join(sb.proj, ".env"), "API=1\n");
  mkdirSync(join(sb.proj, "src"), { recursive: true });
  writeFileSync(join(sb.proj, "src", "a.ts"), "export const a = 1;\n");
}

const DENIED_SHELL = [
  "cat <<E\nE\ncat .env",
  "cat $'.env\\x00junk'",
  "cat .e{m..o}v",
  "cat <<EOF\n`cat .env`\nEOF",
  "sudo -u root cat .env",
  "nice -n 5 cat .env",
  "timeout -k 1 5 cat .env",
  "env -u FOO cat .env",
  "env -S 'cat .env'",
  "doas cat .env",
  "bash -o pipefail -c 'cat .env'",
  "bash -c 'cat $1' x .env",
  'cd "$(echo x)" && cat .env',
  "cat ~root/.env",
  "perl -pe1 .env",
  "xargs -a .env echo",
  'bash <<< "cat .env"',
  "ln -s .env notes.txt && cat notes.txt",
  "mv .env notes.txt",
  "grep -r API .",
  "find . -name '*' -exec cat {} +",
  "tar cf - .",
  "git --git-dir=.git show HEAD:.env",
  "pnpm secretgate disable",
  "npx --package secretgate secretgate disable",
  "yarn secretgate uninstall --all",
];

scenario("shell: each audited bypass is refused or asks", (sb) => {
  shellProject(sb);
  const leaks = DENIED_SHELL.filter((c) => !["deny", "ask"].includes(bash(sb, c)));
  check(leaks.length === 0, `allowed: ${leaks.map((c) => JSON.stringify(c)).join(" | ")}`);
});

scenario("shell: legitimate commands stay allowed", (sb) => {
  shellProject(sb);
  const fine = ["cat > doc.md <<EOF\ncat ~/.ssh/id_rsa\nEOF", "grep -rn --include=*.ts foo src", "cat '[z-a]'", "ls [z-a]", "rg -n export src"];
  const refused = fine.filter((c) => bash(sb, c) !== undefined);
  check(refused.length === 0, `refused: ${refused.map((c) => JSON.stringify(c)).join(" | ")}`);
});

scenario("shell: the anti-disable guard holds during a pause", (sb) => {
  hook(sb, "user-prompt-submit", { session_id: "paused", prompt: "/secretgate off" });
  for (const c of ["secretgate uninstall --all", "secretgate disable --scope"]) {
    const d = bash(sb, c, { session_id: "paused" });
    check(d === "ask" || d === "deny", `'${c}' ran unasked during a pause (${d})`);
  }
});

scenario("scope: cd and substitutions are followed; grep --include is not a path", (sb) => {
  shellProject(sb);
  mkdirSync(join(sb.proj, "secret"), { recursive: true });
  writeFileSync(join(sb.proj, "secret", "x"), "classified\n");
  writeFileSync(join(sb.proj, ".secretgate.json"), JSON.stringify({ scope: { deny: ["secret/**"] } }));
  const refused = ["cd nowhere; cat secret/x", "cd secret && echo $(cat x)", "cd src && git log -p"].filter((c) => bash(sb, c) !== "deny");
  check(refused.length === 0, `allowed out of scope: ${refused.join(" | ")}`);
  writeFileSync(join(sb.proj, ".secretgate.json"), JSON.stringify({ scope: { allow: ["src/**"] } }));
  check(bash(sb, "grep -rn --include=*.ts foo src") === undefined, "grep --include=*.ts read as a path");
});

// ---------------------------------------------------------------- D: installers

scenario("codex: install keeps config.toml valid with dotted feature keys", (sb) => {
  for (const before of [
    'model = "o4"\nfeatures.web_search = true\n',
    "features = { web_search = true }\n",
    "[ features ]\nweb_search = true\n",
    "[features]\r\nweb_search = true\r\n",
  ]) {
    rmSync(sb.env.CODEX_HOME, { recursive: true, force: true });
    mkdirSync(sb.env.CODEX_HOME, { recursive: true });
    writeFileSync(join(sb.env.CODEX_HOME, "config.toml"), before);
    const r = cli(sb, ["install", "--codex"]);
    const after = readFileSync(join(sb.env.CODEX_HOME, "config.toml"), "utf8");
    let parsed;
    try {
      parsed = parseToml(after);
    } catch (err) {
      throw new Error(`invalid TOML after install over ${JSON.stringify(before)}: ${err.message.split("\n")[0]}`);
    }
    check(r.code === 0 ? parsed.features?.hooks === true : r.stderr.includes("hooks = true"), `hooks not enabled over ${JSON.stringify(before)}`);
    check(parsed.features?.web_search === true, "user's feature lost");
  }
});

scenario("codex: reinstall after reordering prunes stale trust entries", (sb) => {
  mkdirSync(sb.env.CODEX_HOME, { recursive: true });
  cli(sb, ["install", "--codex"]);
  const hooksPath = join(sb.env.CODEX_HOME, "hooks.json");
  const hooks = JSON.parse(readFileSync(hooksPath, "utf8"));
  hooks.hooks.PreToolUse.unshift({ matcher: "x", hooks: [{ type: "command", command: "true" }] });
  writeFileSync(hooksPath, JSON.stringify(hooks, null, 2));
  cli(sb, ["install", "--codex"]);
  const toml = parseToml(readFileSync(join(sb.env.CODEX_HOME, "config.toml"), "utf8"));
  const keys = Object.keys(toml.hooks?.state ?? {}).filter((k) => k.includes(":pre_tool_use:"));
  check(keys.length === 1, `pre_tool_use trust keys: ${keys.join(", ")}`);
});

scenario("opencode: uninstall keeps comments and never half-uninstalls", (sb) => {
  const dir = sb.env.OPENCODE_CONFIG_DIR;
  mkdirSync(dir, { recursive: true });
  cli(sb, ["install", "--opencode"]);
  const jsonc = '{\n  // my theme\n  "theme": "dark",\n  "plugin": ["secretgate@1.0.0", "other"],\n}\n';
  writeFileSync(join(dir, "opencode.jsonc"), jsonc);
  const r = cli(sb, ["uninstall", "--opencode"]);
  check(r.code === 0, `uninstall exited ${r.code}: ${r.stderr}`);
  const after = readFileSync(join(dir, "opencode.jsonc"), "utf8");
  check(after.includes("// my theme") && !after.includes("secretgate@") && after.includes('"other"'), `opencode.jsonc after uninstall: ${after}`);
  // A broken config: nothing is removed, the plugin stays.
  cli(sb, ["install", "--opencode"]);
  writeFileSync(join(dir, "opencode.json"), '{ "plugin": [');
  const bad = cli(sb, ["uninstall", "--opencode"]);
  check(bad.code !== 0 && existsSync(join(dir, "plugin", "secretgate.js")), "a failed uninstall removed the plugin anyway");
});

scenario("claude-code: hooks run an absolute node and uninstall leaves no empty hooks", (sb) => {
  const settings = join(sb.home, ".claude", "settings.json");
  mkdirSync(join(sb.home, ".claude"), { recursive: true });
  writeFileSync(settings, JSON.stringify({ theme: "dark" }));
  cli(sb, ["install", "--claude-code"]);
  const wired = JSON.parse(readFileSync(settings, "utf8"));
  const command = wired.hooks.PreToolUse.at(-1).hooks[0].command;
  check(command.startsWith(`"${process.execPath}"`), `hook command does not run an absolute node: ${command}`);
  const run = spawnSync("/bin/sh", ["-c", command], {
    env: { ...sb.env, PATH: "/usr/bin:/bin" },
    input: JSON.stringify({ cwd: sb.proj, tool_name: "Bash", tool_input: { command: "ls" } }),
    encoding: "utf8",
  });
  check(run.status === 0 && run.stdout.trim().startsWith("{"), `hook without node on PATH: exit ${run.status} ${run.stderr.slice(0, 120)}`);
  cli(sb, ["uninstall", "--claude-code"]);
  const after = JSON.parse(readFileSync(settings, "utf8"));
  check(!("hooks" in after), `uninstall left ${JSON.stringify(after)}`);
  const backups = readdirSync(join(sb.home, ".claude")).filter((f) => f.includes("ownership.json.secretgate-backup"));
  check(backups.length <= 1, `${backups.length} ownership backups`);
});

// ---------------------------------------------------------------- run

let failed = 0;
let ran = 0;
for (const { name, fn } of scenarios) {
  if (filter && !name.includes(filter)) continue;
  ran++;
  const sb = sandbox();
  try {
    fn(sb);
    console.log(`PASS  ${name}`);
  } catch (err) {
    failed++;
    console.log(`FAIL  ${name}\n      ${String(err.message).split("\n").join("\n      ")}`);
  } finally {
    sb.cleanup();
  }
}
console.log(`\n${ran - failed}/${ran} scenarios pass`);
process.exit(failed > 0 ? 1 : 0);
