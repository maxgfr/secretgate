import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { handleCodex } from "../../src/hooks/codex.js";
import { Vault } from "../../src/vault/vault.js";
import { FAKE } from "../fixtures/fake-tokens.js";

// The Codex adapter: same scanner as Claude Code, Codex-shaped answers.

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "secretgate-codex-"));
  process.env.SECRETGATE_HOME = home;
});

afterEach(() => {
  delete process.env.SECRETGATE_HOME;
  delete process.env.SECRETGATE_DISABLE;
  rmSync(home, { recursive: true, force: true });
});

const ev = (hook_event_name: string, extra: Record<string, unknown>) => JSON.stringify({ session_id: "c1", cwd: home, hook_event_name, ...extra });
const pre = (tool_name: string, tool_input: unknown) => ev("PreToolUse", { tool_name, tool_input });

describe("Codex PreToolUse", () => {
  it("abstains with EMPTY stdout (the {} workaround is Claude-only)", async () => {
    expect(await handleCodex("pre-tool-use", pre("Bash", { command: "ls" }))).toEqual({ stdout: "", exit: 0 });
  });

  it.each([
    ["Bash", { command: "cat ~/.ssh/id_rsa" }],
    ["exec_command", { cmd: "cat ~/.ssh/id_rsa" }],
    ["shell", { command: ["cat", "/home/u/.ssh/id_rsa"] }],
    ["shell", { command: ["bash", "-lc", "head -1 ~/.aws/credentials"] }],
  ])("denies a sensitive read through %s", async (tool, input) => {
    const out = JSON.parse((await handleCodex("pre-tool-use", pre(tool, input))).stdout);
    expect(out.hookSpecificOutput.permissionDecision).toBe("deny");
  });

  it("restores placeholders in apply_patch with the allow Codex requires", async () => {
    const placeholder = new Vault().recordSecret(FAKE.githubPat, "github-pat", "test");
    const patch = `*** Begin Patch\n*** Add File: copy.txt\n+${placeholder}\n*** End Patch`;
    const out = JSON.parse((await handleCodex("pre-tool-use", pre("apply_patch", { command: patch }))).stdout);
    expect(out.hookSpecificOutput.permissionDecision).toBe("allow");
    expect(out.hookSpecificOutput.updatedInput.command).toContain(FAKE.githubPat);
  });

  it("turns an `ask` into a deny that hands the decision back to the user", async () => {
    const out = JSON.parse((await handleCodex("pre-tool-use", pre("exec_command", { cmd: "secretgate disable --forever" }))).stdout);
    expect(out.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(out.hookSpecificOutput.permissionDecisionReason).toMatch(/Codex cannot ask/);
  });
});

describe("Codex PostToolUse", () => {
  it("blocks the raw result and returns only a redacted replacement", async () => {
    const r = await handleCodex(
      "post-tool-use",
      ev("PostToolUse", { tool_name: "Bash", tool_input: { command: "env" }, tool_response: `T=${FAKE.githubPat}` }),
    );
    const out = JSON.parse(r.stdout);
    expect(out.decision).toBe("block");
    expect(out.reason).toMatch(/SECRETGATE_/);
    expect(r.stdout).not.toContain(FAKE.githubPat);
  });

  it("says nothing on clean output", async () => {
    expect((await handleCodex("post-tool-use", ev("PostToolUse", { tool_name: "Bash", tool_input: {}, tool_response: "ok" }))).stdout).toBe("");
  });

  it("withholds (never passes) output it cannot scan", async () => {
    const out = JSON.parse((await handleCodex("post-tool-use", "{broken")).stdout);
    expect(out.decision).toBe("block");
  });
});

describe("Codex UserPromptSubmit", () => {
  it("blocks a secret-bearing prompt without echoing it", async () => {
    const r = await handleCodex("user-prompt-submit", ev("UserPromptSubmit", { prompt: `key ${FAKE.githubPat}` }));
    expect(JSON.parse(r.stdout).decision).toBe("block");
    expect(r.stdout).not.toContain(FAKE.githubPat);
  });

  it("honors [allow-secret]", async () => {
    expect((await handleCodex("user-prompt-submit", ev("UserPromptSubmit", { prompt: `[allow-secret] key ${FAKE.githubPat}` }))).stdout).toBe("");
  });
});
