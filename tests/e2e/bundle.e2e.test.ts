import { execFile } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { FAKE } from "../fixtures/fake-tokens.js";

const execFileP = promisify(execFile);
const BUNDLE = join(__dirname, "..", "..", "scripts", "secretgate.mjs");

// End-to-end over the COMMITTED bundle (what agents actually invoke). CI runs
// check:build before tests, so the bundle is guaranteed fresh there.
let home: string;
let env: NodeJS.ProcessEnv;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "secretgate-e2e-"));
  env = { ...process.env, HOME: home, SECRETGATE_HOME: join(home, ".secretgate") };
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

function runBundle(args: string[], stdin?: string): Promise<{ stdout: string; stderr: string; code: number; ms: number }> {
  return new Promise((resolvePromise) => {
    const t0 = performance.now();
    const child = execFile("node", [BUNDLE, ...args], { env }, (err, stdout, stderr) => {
      resolvePromise({ stdout, stderr, code: child.exitCode ?? (err ? 1 : 0), ms: performance.now() - t0 });
    });
    if (stdin !== undefined) child.stdin!.end(stdin);
    else child.stdin!.end();
  });
}

describe.skipIf(!existsSync(BUNDLE))("bundle e2e", () => {
  it("blocks a secret-bearing prompt through the real hook entrypoint, fast", async () => {
    const event = JSON.stringify({ hook_event_name: "UserPromptSubmit", cwd: home, prompt: `deploy with ${FAKE.githubPat}` });
    const r = await runBundle(["hook", "claude-code", "user-prompt-submit"], event);
    expect(r.code).toBe(0);
    const out = JSON.parse(r.stdout);
    expect(out.decision).toBe("block");
    expect(out.reason).not.toContain(FAKE.githubPat);
    // whole-process budget (spawn + node boot + rules compile + scan)
    expect(r.ms).toBeLessThan(1500);
  });

  it("redacts tool output and restores it on write — full round trip", async () => {
    const post = JSON.stringify({
      hook_event_name: "PostToolUse",
      cwd: home,
      tool_name: "Read",
      tool_input: { file_path: "/x/.env.ci" },
      tool_response: { file: { content: `TOKEN=${FAKE.githubPat}\n` } },
    });
    const r1 = await runBundle(["hook", "claude-code", "post-tool-use"], post);
    const placeholder = JSON.parse(r1.stdout).hookSpecificOutput.updatedToolOutput.file.content.match(/SECRETGATE_[0-9a-f]{12,16}/)![0];

    const pre = JSON.stringify({
      hook_event_name: "PreToolUse",
      cwd: home,
      tool_name: "Write",
      tool_input: { file_path: "/x/copy.env", content: `TOKEN=${placeholder}\n` },
    });
    const r2 = await runBundle(["hook", "claude-code", "pre-tool-use"], pre);
    expect(JSON.parse(r2.stdout).hookSpecificOutput.updatedInput.content).toBe(`TOKEN=${FAKE.githubPat}\n`);
  });

  it("install --claude-code wires ~/.claude/settings.json idempotently; uninstall unwires", async () => {
    const r1 = await runBundle(["install", "--claude-code"]);
    expect(r1.code).toBe(0);
    const settingsPath = join(home, ".claude", "settings.json");
    const s = JSON.parse(readFileSync(settingsPath, "utf8"));
    expect(s.hooks.UserPromptSubmit[0].hooks[0].command).toContain("hook claude-code user-prompt-submit");
    expect(s.hooks.UserPromptSubmit[0].hooks[0].command).toContain(".secretgate/bin/secretgate.mjs");
    expect(s.permissions.deny).toContain("Read(**/.env)");
    // the pinned bundle copy exists and is runnable
    const pinned = join(home, ".secretgate", "bin", "secretgate.mjs");
    expect(existsSync(pinned)).toBe(true);

    const r2 = await runBundle(["install", "--claude-code"]);
    expect(r2.stdout).toContain("already up to date");

    const r3 = await runBundle(["uninstall", "--claude-code"]);
    expect(r3.code).toBe(0);
    const s2 = JSON.parse(readFileSync(settingsPath, "utf8"));
    expect(s2.hooks?.UserPromptSubmit).toBeUndefined();
    expect(s2.permissions?.deny ?? []).not.toContain("Read(**/.env)");
  });
});
