import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { handleClaudeCode } from "../../src/hooks/claude-code.js";
import { handleCodex } from "../../src/hooks/codex.js";
import { isStoppedSession } from "../../src/hooks/stopped-session.js";
import { Vault } from "../../src/vault/vault.js";
import { type EngineLoader, setEngineLoader, VERIFIER_RULE_ID } from "../../src/verifier/verifier.js";
import { FAKE } from "../fixtures/fake-tokens.js";

// The hooks with the verifier on, and a FAKE engine (no assets): what it
// redacts, what it leaves to the rules, and what it must never do.
const value = ["Qm7", "xR2", "pL9", "vN4", "kT8"].join("");
let home: string;
let loads: number;
let seen: Array<Record<string, unknown>>;

const engine =
  (p: (c: Record<string, unknown>) => number): EngineLoader =>
  () => {
    loads++;
    return {
      build: "simd128",
      tau: 0.5,
      judge: (c) => {
        seen.push(c);
        return p(c);
      },
      state: () => "",
    };
  };

function verifierConfig(entry: unknown): void {
  writeFileSync(join(home, "config.json"), JSON.stringify({ verifier: entry }));
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "secretgate-vh-"));
  process.env.SECRETGATE_HOME = home;
  loads = 0;
  seen = [];
  setEngineLoader(engine(() => 0.9));
});
afterEach(() => {
  setEngineLoader(undefined);
  delete process.env.SECRETGATE_HOME;
  rmSync(home, { recursive: true, force: true });
});

const post = (tool_name: string, tool_input: unknown, tool_response: unknown, cwd = "/tmp") =>
  JSON.stringify({ session_id: "s1", hook_event_name: "PostToolUse", cwd, tool_name, tool_input, tool_response });
const bash = (stdout: string) => post("Bash", { command: "env" }, { stdout, stderr: "", interrupted: false, isImage: false });
const output = (r: { stdout: string }) => (r.stdout ? JSON.parse(r.stdout).hookSpecificOutput?.updatedToolOutput : undefined);
const batch = (...calls: Array<{ tool_name: string; tool_response: unknown }>) =>
  JSON.stringify({
    session_id: "s1",
    hook_event_name: "PostToolBatch",
    cwd: "/tmp",
    tool_calls: calls.map((c, i) => ({ tool_input: {}, tool_use_id: `t${i}`, ...c })),
  });

describe("the verifier in the hooks", () => {
  it("is off by default: the output is exactly what the rules give, and the engine is never loaded", async () => {
    const r = await handleClaudeCode("post-tool-use", bash(`DB_PASS=${value}\n`));
    expect(r).toEqual({ stdout: "", exit: 0 });
    verifierConfig({ enabled: false });
    expect(await handleClaudeCode("post-tool-use", bash(`DB_PASS=${value}\n`))).toEqual({ stdout: "", exit: 0 });
    expect(loads).toBe(0);
  });

  it("redacts what it accepts, under its own rule id, and the placeholder is restored on the way back", async () => {
    verifierConfig({ enabled: true });
    const r = await handleClaudeCode("post-tool-use", bash(`HOME=/x\nDB_PASS=${value}\n`));
    expect(r.exit).toBe(0);
    expect(r.stdout).not.toContain(value);
    const stdout = output(r).stdout as string;
    expect(stdout).toMatch(/^HOME=\/x\nDB_PASS=SECRETGATE_[0-9a-f]{12}\n$/);
    const placeholder = /SECRETGATE_[0-9a-f]{12}/.exec(stdout)![0];
    expect(new Vault().list()).toEqual([expect.objectContaining({ placeholder, ruleId: VERIFIER_RULE_ID, sources: ["claude-code:Bash"] })]);
    const write = await handleClaudeCode(
      "pre-tool-use",
      JSON.stringify({ session_id: "s1", cwd: "/tmp", tool_name: "Write", tool_input: { file_path: "/tmp/x.env", content: `DB_PASS=${placeholder}\n` } }),
    );
    expect(JSON.parse(write.stdout).hookSpecificOutput.updatedInput.content).toBe(`DB_PASS=${value}\n`);
  });

  it("leaves a value a rule found to the rule: same placeholder, same rule id as without it", async () => {
    const text = `GITHUB_TOKEN=${FAKE.githubPat}\n`;
    const off = output(await handleClaudeCode("post-tool-use", bash(text))).stdout;
    rmSync(join(home, "vault.json"), { force: true });
    verifierConfig({ enabled: true });
    const on = output(await handleClaudeCode("post-tool-use", bash(text))).stdout;
    expect(on).toBe(off);
    expect(new Vault().list().map((e) => e.ruleId)).toEqual(["github-pat"]);
    expect(seen).toEqual([]);
  });

  it("is skipped when its assets are missing: the output is the rules' output", async () => {
    setEngineLoader(undefined); // the real loader; the data directory is empty
    verifierConfig({ enabled: true });
    const text = `GITHUB_TOKEN=${FAKE.githubPat}\nDB_PASS=${value}\n`;
    const r = await handleClaudeCode("post-tool-use", bash(text));
    expect(r.exit).toBe(0);
    const stdout = output(r).stdout as string;
    expect(stdout).toContain(`DB_PASS=${value}`);
    expect(stdout).not.toContain(FAKE.githubPat);
  });

  it("is skipped, never fails closed, when the engine throws on load or on a candidate", async () => {
    verifierConfig({ enabled: true });
    setEngineLoader(() => {
      throw new Error("CompileError");
    });
    const a = await handleClaudeCode("post-tool-use", bash(`DB_PASS=${value}\n`));
    expect(a).toEqual({ stdout: "", exit: 0 });
    setEngineLoader(
      engine(() => {
        throw new Error("RuntimeError: unreachable");
      }),
    );
    const b = await handleClaudeCode("post-tool-use", bash(`DB_PASS=${value}\n`));
    expect(b).toEqual({ stdout: "", exit: 0 });
  });

  it("is skipped when the config entry is invalid", async () => {
    verifierConfig({ enabled: true, threshold: "f9" });
    expect(await handleClaudeCode("post-tool-use", bash(`DB_PASS=${value}\n`))).toEqual({ stdout: "", exit: 0 });
    expect(loads).toBe(0);
  });

  it("gives the model a Read's path below the repository, and no path for any other tool", async () => {
    verifierConfig({ enabled: true });
    setEngineLoader(engine(() => 0.1));
    const repo = mkdtempSync(join(tmpdir(), "secretgate-vh-repo-"));
    try {
      mkdirSync(join(repo, ".git"));
      const file = join(repo, "conf", "app.env");
      await handleClaudeCode(
        "post-tool-use",
        post(
          "Read",
          { file_path: file },
          { type: "text", file: { filePath: file, content: `DB_PASS=${value}\n`, numLines: 1, startLine: 1, totalLines: 1 } },
          repo,
        ),
      );
      await handleClaudeCode("post-tool-use", post("Bash", { command: `cat ${file}` }, { stdout: `DB_PASS=${value}\n`, stderr: "" }, repo));
      await handleClaudeCode(
        "post-tool-use",
        post("Read", { file_path: "/etc/app.env" }, { type: "text", file: { filePath: "/etc/app.env", content: `DB_PASS=${value}\n` } }, repo),
      );
      expect(seen.map((c) => c.file)).toEqual(["conf/app.env", null, null]);
    } finally {
      rmSync(repo, { recursive: true, force: true });
    }
  });

  it("never blocks a prompt: a prompt the rules let through is let through", async () => {
    verifierConfig({ enabled: true });
    const r = await handleClaudeCode("user-prompt-submit", JSON.stringify({ session_id: "s1", cwd: "/tmp", prompt: `the db is DB_PASS=${value}` }));
    expect(r).toEqual({ stdout: "", exit: 0 });
    expect(loads).toBe(0);
  });

  it("redacts in Codex too, through its block-and-replace", async () => {
    verifierConfig({ enabled: true });
    const r = await handleCodex("post-tool-use", bash(`DB_PASS=${value}\n`));
    const out = JSON.parse(r.stdout);
    expect(out.decision).toBe("block");
    expect(out.reason).toMatch(/DB_PASS=SECRETGATE_[0-9a-f]{12}/);
    expect(r.stdout).not.toContain(value);
  });
});

describe("the verifier at the PostToolBatch gate", () => {
  const failed = { tool_name: "Bash", tool_response: `Exit code 1\nDB_PASS=${value}\n` };

  it("reports a verifier-only detection in a failed call, without stopping the turn or closing the session", async () => {
    verifierConfig({ enabled: true });
    const r = await handleClaudeCode("post-tool-batch", batch({ tool_name: "Read", tool_response: "const a = 1;" }, failed));
    expect(r.exit).toBe(0);
    const out = JSON.parse(r.stdout);
    expect(out.continue).toBeUndefined();
    expect(out.stopReason).toBeUndefined();
    expect(out.systemMessage).toContain(VERIFIER_RULE_ID);
    expect(out.systemMessage).toContain("NOT redacted");
    expect(out.systemMessage).toContain("Bash");
    expect(out.systemMessage).not.toContain("Read");
    expect(r.stdout).not.toContain(value);
    expect(isStoppedSession("s1")).toBe(false);
    const next = await handleClaudeCode("user-prompt-submit", JSON.stringify({ session_id: "s1", cwd: "/tmp", prompt: "go on" }));
    expect(next).toEqual({ stdout: "", exit: 0 });
  });

  it("stays silent when it is off or accepts nothing", async () => {
    expect(await handleClaudeCode("post-tool-batch", batch(failed))).toEqual({ stdout: "", exit: 0 });
    verifierConfig({ enabled: true });
    setEngineLoader(engine(() => 0.1));
    expect(await handleClaudeCode("post-tool-batch", batch(failed))).toEqual({ stdout: "", exit: 0 });
  });

  it("leaves the stop to the rules: a rule finding stops the turn as before", async () => {
    verifierConfig({ enabled: true });
    const r = await handleClaudeCode("post-tool-batch", batch({ tool_name: "Bash", tool_response: `Exit code 1\nT=${FAKE.githubPat}\nDB_PASS=${value}\n` }));
    const out = JSON.parse(r.stdout);
    expect(out.continue).toBe(false);
    expect(out.stopReason).toContain("github-pat");
    expect(out.stopReason).not.toContain(VERIFIER_RULE_ID);
  });

  it("finds nothing in a result PostToolUse already redacted with it", async () => {
    verifierConfig({ enabled: true });
    const redacted = output(await handleClaudeCode("post-tool-use", bash(`DB_PASS=${value}\n`))).stdout as string;
    seen = [];
    expect(await handleClaudeCode("post-tool-batch", batch({ tool_name: "Bash", tool_response: redacted }))).toEqual({ stdout: "", exit: 0 });
    expect(seen).toEqual([]);
  });
});
