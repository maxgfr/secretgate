import { execFile } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { FAKE } from "../fixtures/fake-tokens.js";

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

  it("protects Codex tool output through block-and-replace without echoing the raw secret", async () => {
    const post = JSON.stringify({
      hook_event_name: "PostToolUse",
      cwd: home,
      tool_name: "Bash",
      tool_input: { command: "env" },
      tool_response: `PATH=/bin\nTOKEN=${FAKE.githubPat}\n`,
    });
    const r = await runBundle(["hook", "codex", "post-tool-use"], post);
    const out = JSON.parse(r.stdout);

    expect(r.code).toBe(0);
    expect(out.decision).toBe("block");
    expect(out.reason).toContain("PATH=/bin");
    expect(out.reason).toMatch(/SECRETGATE_[0-9a-f]{12,16}/);
    expect(r.stdout).not.toContain(FAKE.githubPat);
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

  it("the OpenCode plugin bundle exports ONLY functions (OpenCode rejects non-function exports)", async () => {
    // Regression: exporting a version string alongside the plugin made OpenCode
    // fail to load it entirely ("Plugin export is not a function").
    const pluginBundle = join(__dirname, "..", "..", "scripts", "secretgate-opencode.mjs");
    const mod = await import(pluginBundle);
    const exports = Object.entries(mod).filter(([k]) => k !== "default");
    expect(exports.length).toBeGreaterThan(0);
    for (const [name, val] of exports) {
      expect(typeof val, `export ${name} must be a function`).toBe("function");
    }
    expect(typeof (mod as any).SecretgatePlugin).toBe("function");
  });

  it("runs when invoked through a SYMLINKED path (macOS /tmp, symlinked homes)", async () => {
    // Regression: the entrypoint guard compared as-typed vs real paths, so a
    // symlinked invocation exited 0 with no output (silent fail-open).
    const linkDir = join(home, "linked");
    symlinkSync(join(__dirname, "..", ".."), linkDir);
    const linkedBundle = join(linkDir, "scripts", "secretgate.mjs");
    const r = await new Promise<{ stdout: string; code: number }>((res) => {
      const child = execFile("node", [linkedBundle, "hook", "claude-code", "user-prompt-submit"], { env }, (_e, stdout) => {
        res({ stdout, code: child.exitCode ?? 0 });
      });
      child.stdin!.end(JSON.stringify({ hook_event_name: "UserPromptSubmit", cwd: home, prompt: `token ${FAKE.githubPat}` }));
    });
    expect(JSON.parse(r.stdout).decision).toBe("block");
  });

  it("init auto-detects Claude Code, installs, and self-verifies the firewall fires", async () => {
    // simulate Claude Code being present
    const { mkdirSync } = await import("node:fs");
    mkdirSync(join(home, ".claude"), { recursive: true });
    const r = await runBundle(["init"]);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("detected Claude Code");
    expect(r.stdout).toContain("a secret pasted in a prompt is blocked");
    expect(r.stdout).toContain("a secret in tool output is redacted");
    expect(r.stdout).toContain("secretgate installed; local checks passed");
    // and it never printed the raw fake token
    expect(r.stdout).not.toMatch(/ghp_[A-Za-z0-9]{36}/);
  });

  it("PostToolUse fails CLOSED on an oversized tool output (withholds, never leaks)", async () => {
    // >20MB tool_response containing a token must be WITHHELD, not passed raw
    const big = "x".repeat(21 * 1024 * 1024);
    const payload = JSON.stringify({
      hook_event_name: "PostToolUse",
      cwd: home,
      tool_name: "Bash",
      tool_input: { command: "cat big.log" },
      tool_response: `${big}\nTOKEN=${FAKE.githubPat}\n`,
    });
    const r = await runBundle(["hook", "claude-code", "post-tool-use"], payload);
    const out = JSON.parse(r.stdout);
    expect(out.hookSpecificOutput.updatedToolOutput.stdout).toMatch(/secretgate withheld/);
    expect(r.stdout).not.toContain(FAKE.githubPat);
  });

  it("status reports wiring per agent and vault health", async () => {
    await runBundle(["install", "--claude-code"]);
    const r = await runBundle(["status"]);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("claude-code global   wired");
    expect(r.stdout).toContain("codex     not wired");
    expect(r.stdout).toContain("opencode  not wired");
    expect(r.stdout).toContain("vault");
  });

  // The env scope is the one an agent inherits from the shell that launched it,
  // so it has to work in a real spawned process — not just in-process.
  it("SECRETGATE_DISABLE=1 stops the block in a real spawned hook, and restore still runs", async () => {
    const prompt = JSON.stringify({ hook_event_name: "UserPromptSubmit", cwd: home, session_id: "e2e", prompt: `deploy with ${FAKE.githubPat}` });
    expect(JSON.parse((await runBundle(["hook", "claude-code", "user-prompt-submit"], prompt)).stdout).decision).toBe("block");

    // stash a placeholder while still enabled, then turn the firewall off
    const piped = await runBundle(["pipe"], `TOKEN=${FAKE.githubPat}\n`);
    const placeholder = piped.stdout.match(/SECRETGATE_[0-9a-f]{12,16}/)![0];

    env.SECRETGATE_DISABLE = "1";
    const off = await runBundle(["hook", "claude-code", "user-prompt-submit"], prompt);
    const out = JSON.parse(off.stdout);
    expect(out.decision).toBeUndefined();
    expect(out.systemMessage).toMatch(/secretgate is DISABLED/);

    const write = JSON.stringify({
      hook_event_name: "PreToolUse",
      cwd: home,
      tool_name: "Write",
      tool_input: { file_path: "/x/copy.env", content: `TOKEN=${placeholder}\n` },
    });
    const restored = await runBundle(["hook", "claude-code", "pre-tool-use"], write);
    expect(JSON.parse(restored.stdout).hookSpecificOutput.updatedInput.content).toBe(`TOKEN=${FAKE.githubPat}\n`);
  });

  it("`disable` then `enable` round-trips through the real hook, and status shouts in between", async () => {
    const prompt = JSON.stringify({ hook_event_name: "UserPromptSubmit", cwd: home, session_id: "e2e", prompt: `deploy with ${FAKE.githubPat}` });
    const d = await runBundle(["disable", "--project", "--minutes", "10"]);
    expect(d.code).toBe(0);
    expect(d.stdout).toContain("DISABLED for directory");

    // the pause is recorded for the process cwd (the repo), not for `home`,
    // so a hook reporting a different cwd stays protected — assert both ways
    expect(JSON.parse((await runBundle(["hook", "claude-code", "user-prompt-submit"], prompt)).stdout).decision).toBe("block");

    const here = JSON.stringify({ hook_event_name: "UserPromptSubmit", cwd: process.cwd(), session_id: "e2e", prompt: `deploy with ${FAKE.githubPat}` });
    expect(JSON.parse((await runBundle(["hook", "claude-code", "user-prompt-submit"], here)).stdout).decision).toBeUndefined();

    expect((await runBundle(["status"])).stdout).toContain("DISABLED");

    expect((await runBundle(["enable", "--project"])).stdout).toContain("re-enabled for directory");
    expect(JSON.parse((await runBundle(["hook", "claude-code", "user-prompt-submit"], here)).stdout).decision).toBe("block");
  });

  it("init self-verifies green even when the shell that runs it has secretgate disabled", async () => {
    const { mkdirSync } = await import("node:fs");
    mkdirSync(join(home, ".claude"), { recursive: true });
    env.SECRETGATE_DISABLE = "1";
    const r = await runBundle(["init"]);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("a secret pasted in a prompt is blocked");
    expect(r.stdout).toContain("secretgate installed; local checks passed");
  });
});
