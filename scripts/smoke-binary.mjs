#!/usr/bin/env node
// Smoke-test a compiled secretgate binary the way Homebrew users get it:
//   node scripts/smoke-binary.mjs dist/secretgate-<platform>-<arch>
// In a throwaway HOME with fake Claude Code / Codex / OpenCode config dirs, and
// with NO node on PATH, it asserts the binary scans, wires every agent to the
// pinned binary (never `node …`), passes init's own self-tests, and that the
// wired hook command really blocks a secret. A hook that silently prints
// nothing is fail-open, so every check reads the actual output.
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const binary = resolve(process.argv[2] ?? "");
if (!process.argv[2] || !existsSync(binary)) {
  console.error("usage: node scripts/smoke-binary.mjs <path to a compiled secretgate binary>");
  process.exit(2);
}
const expectedVersion = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version;

// high-entropy fake token, built by concatenation (never a literal in-repo)
const fake = "ghp_" + ["aB3dE6", "gH9jK2", "mN5pQ8", "sT1vW4", "yZ7bC0", "dF6hJ9"].join("");

const home = mkdtempSync(join(tmpdir(), "secretgate-smoke-"));
const noNodePath = join(home, "empty-path"); // PATH with nothing on it: no node, no bun
for (const d of [".claude", ".codex", join(".config", "opencode"), "empty-path"]) mkdirSync(join(home, d), { recursive: true });
const env = { HOME: home, PATH: noNodePath, TMPDIR: tmpdir() };

let failures = 0;
const check = (ok, message, detail) => {
  console.log(`${ok ? "  ok  " : "  FAIL"} ${message}`);
  if (!ok) {
    failures++;
    if (detail) console.log(String(detail).replace(/^/gm, "       "));
  }
};
const exec = (file, args, input) => {
  const r = spawnSync(file, args, { env, input, encoding: "utf8", timeout: 60000, cwd: home, maxBuffer: 64 * 1024 * 1024 });
  if (r.error) throw new Error(`could not run ${file}: ${r.error.message}`);
  return r;
};

try {
  const version = exec(binary, ["--version"]);
  check(version.status === 0 && version.stdout.trim() === expectedVersion, `--version prints ${expectedVersion}`, version.stdout + version.stderr);

  const scan = exec(binary, ["scan", "-"], `aws key AKIA${"Q7R2M3XBL4WPZ6TK"} and ${fake}\n`);
  check(scan.status === 1, "scan - exits 1 on a fake token", `exit ${scan.status}\n${scan.stdout}${scan.stderr}`);

  const init = exec(binary, ["init", "--all"]);
  const out = init.stdout;
  check(init.status === 0, "init --all exits 0", `exit ${init.status}\n${out}${init.stderr}`);
  check(!out.includes("✗"), "no init self-test failed", out);
  for (const probe of ["a secret pasted in a prompt is blocked", "codex: a secret pasted in a prompt is blocked", "opencode: installed plugin passes"])
    check(out.includes(`✓ ${probe}`), `init self-test ran: ${probe}`, out);

  const pinned = join(home, ".secretgate", "bin", "secretgate");
  check(existsSync(pinned), `the binary is pinned at ${pinned}`);

  const commandsOf = (file) => {
    const hooks = JSON.parse(readFileSync(file, "utf8")).hooks ?? {};
    return Object.values(hooks).flatMap((groups) => groups.flatMap((g) => (g.hooks ?? []).map((h) => h.command)));
  };
  const wired = {
    "claude-code": commandsOf(join(home, ".claude", "settings.json")).filter((c) => / hook claude-code /.test(c)),
    codex: commandsOf(join(home, ".codex", "hooks.json")).filter((c) => / hook codex /.test(c)),
  };
  for (const [agent, commands] of Object.entries(wired)) {
    check(commands.length > 0, `${agent}: hooks are wired`);
    const bad = commands.filter((c) => !c.startsWith(`"${pinned}" hook `) || /\bnode\b/.test(c));
    check(bad.length === 0, `${agent}: every hook runs the pinned binary, without node`, bad.join("\n"));
  }

  // Run the wired hook command exactly as the agent's shell would — no node on PATH.
  const prompt = wired["claude-code"].find((c) => c.endsWith(" user-prompt-submit"));
  if (prompt) {
    const r = exec("/bin/sh", ["-c", prompt], JSON.stringify({ hook_event_name: "UserPromptSubmit", cwd: home, prompt: `deploy with ${fake}` }));
    let decision;
    try {
      decision = JSON.parse(r.stdout).decision;
    } catch {}
    check(decision === "block" && !r.stdout.includes(fake), "the wired user-prompt-submit hook blocks a secret with no node on PATH", r.stdout + r.stderr);
  } else check(false, "claude-code: a user-prompt-submit hook is wired");

  // A large tool output must come back whole: a truncated JSON answer is no
  // answer. Kept under the hooks' 2 MB scan cap, past which output is withheld.
  const big = `${"log line\n".repeat(150000)}TOKEN=${fake}\n`;
  const post = exec(pinned, ["hook", "claude-code", "post-tool-use"], JSON.stringify({ hook_event_name: "PostToolUse", cwd: home, tool_name: "Bash", tool_input: { command: "cat big.log" }, tool_response: big }));
  let redacted = "";
  try {
    redacted = JSON.stringify(JSON.parse(post.stdout).hookSpecificOutput.updatedToolOutput);
  } catch {}
  check(redacted.includes("SECRETGATE_") && !post.stdout.includes(fake), `a ${(big.length / 1e6).toFixed(1)} MB tool output is redacted and returned whole`, post.stderr || post.stdout.slice(0, 300));

  const status = exec(binary, ["status"]);
  check(status.status === 0 && status.stdout.includes(`binary    pinned at ${pinned} (v${expectedVersion})`), "status reports the pinned binary and its version", status.stdout);
  check(!status.stdout.includes("MISSING"), "status finds every hook program", status.stdout);
} finally {
  rmSync(home, { recursive: true, force: true });
}

if (failures > 0) {
  console.error(`smoke-binary: ${failures} check(s) failed`);
  process.exit(1);
}
console.log(`smoke-binary: ${binary} OK`);
