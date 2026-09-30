import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { addPause, disableState } from "../../src/disable.js";
import { handleClaudeCode } from "../../src/hooks/claude-code.js";
import { handleCodex } from "../../src/hooks/codex.js";
import { FAKE } from "../fixtures/fake-tokens.js";

let home: string;
let proj: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "secretgate-sh-home-"));
  process.env.SECRETGATE_HOME = home;
  proj = realpathSync(mkdtempSync(join(tmpdir(), "secretgate-sh-proj-")));
  mkdirSync(join(proj, ".git"));
  for (const d of ["src", "docs", "tests"]) mkdirSync(join(proj, d));
  writeFileSync(join(proj, "src", "main.ts"), "export {}\n");
  writeFileSync(join(proj, "docs", "guide.md"), "# guide\n");
  writeFileSync(join(proj, "tests", "a.test.ts"), "x\n");
  writeFileSync(join(proj, ".secretgate.json"), JSON.stringify({ scope: { allow: ["src/**", "tests/**"] } }));
});

afterEach(() => {
  delete process.env.SECRETGATE_HOME;
  delete process.env.SECRETGATE_DISABLE;
  rmSync(home, { recursive: true, force: true });
  rmSync(proj, { recursive: true, force: true });
});

const ev = (extra: Record<string, unknown>) => JSON.stringify({ session_id: "s1", cwd: proj, ...extra });
const pre = (tool_name: string, tool_input: unknown) => ev({ hook_event_name: "PreToolUse", tool_name, tool_input });
const post = (tool_name: string, tool_input: unknown, tool_response: unknown) => ev({ hook_event_name: "PostToolUse", tool_name, tool_input, tool_response });
const prompt = (text: string, session = "s1") => JSON.stringify({ session_id: session, cwd: proj, hook_event_name: "UserPromptSubmit", prompt: text });
const decision = (stdout: string) => (stdout.trim() ? JSON.parse(stdout).hookSpecificOutput?.permissionDecision : undefined);

describe("scope — Claude Code hooks", () => {
  it("denies reads, edits and shell commands outside the scope", async () => {
    expect(decision((await handleClaudeCode("pre-tool-use", pre("Read", { file_path: join(proj, "docs/guide.md") }))).stdout)).toBe("deny");
    expect(decision((await handleClaudeCode("pre-tool-use", pre("Edit", { file_path: "docs/guide.md" }))).stdout)).toBe("deny");
    expect(decision((await handleClaudeCode("pre-tool-use", pre("Bash", { command: "cat docs/guide.md" }))).stdout)).toBe("deny");
    expect(decision((await handleClaudeCode("pre-tool-use", pre("LS", { path: join(proj, "docs") }))).stdout)).toBe("deny");
    expect((await handleClaudeCode("pre-tool-use", pre("Read", { file_path: join(proj, "src/main.ts") }))).stdout).toBe("{}");
  });

  it("works from a subdirectory (config found upwards)", async () => {
    const r = await handleClaudeCode(
      "pre-tool-use",
      JSON.stringify({ session_id: "s1", cwd: join(proj, "src"), tool_name: "Read", tool_input: { file_path: "../docs/guide.md" } }),
    );
    expect(decision(r.stdout)).toBe("deny");
  });

  it("filters out-of-scope entries from Glob/Grep results", async () => {
    const r = await handleClaudeCode(
      "post-tool-use",
      post("Glob", { pattern: "**/*" }, { filenames: [join(proj, "src/main.ts"), join(proj, "docs/guide.md")], numFiles: 2, truncated: false }),
    );
    const out = JSON.parse(r.stdout).hookSpecificOutput.updatedToolOutput;
    expect(out.filenames).toEqual([join(proj, "src/main.ts")]);
    expect(out.numFiles).toBe(1);
  });

  it("blocks an @mention of an out-of-scope file in the prompt", async () => {
    const r = await handleClaudeCode("user-prompt-submit", prompt("résume @docs/guide.md"));
    expect(JSON.parse(r.stdout).decision).toBe("block");
    expect((await handleClaudeCode("user-prompt-submit", prompt("résume @src/main.ts"))).stdout).toBe("");
  });

  it("stays enforced while secretgate is disabled…", async () => {
    addPause({ scope: "session", target: "s1", minutes: 60 });
    expect(decision((await handleClaudeCode("pre-tool-use", pre("Read", { file_path: "docs/guide.md" }))).stdout)).toBe("deny");
    expect(JSON.parse((await handleClaudeCode("user-prompt-submit", prompt("lis @docs/guide.md"))).stdout).decision).toBe("block");
  });

  it("…unless the pause explicitly lifts it (disable --scope)", async () => {
    addPause({ scope: "session", target: "s1", minutes: 60, liftScope: true });
    expect((await handleClaudeCode("pre-tool-use", pre("Read", { file_path: "docs/guide.md" }))).stdout).toBe("{}");
  });

  it("fails closed on an invalid .secretgate.json, but lets the agent fix it", async () => {
    writeFileSync(join(proj, ".secretgate.json"), JSON.stringify({ scope: { allow: "src/**" } }));
    const r = await handleClaudeCode("pre-tool-use", pre("Read", { file_path: "src/main.ts" }));
    expect(decision(r.stdout)).toBe("deny");
    expect(JSON.parse(r.stdout).hookSpecificOutput.permissionDecisionReason).toMatch(/invalid/);
    expect(decision((await handleClaudeCode("pre-tool-use", pre("Edit", { file_path: ".secretgate.json" }))).stdout)).not.toBe("deny");
  });
});

describe("scope — Codex hook shapes", () => {
  it("denies exec_command {cmd}, shell {command: []} and apply_patch outside the scope", async () => {
    expect(decision((await handleCodex("pre-tool-use", pre("exec_command", { cmd: "cat docs/guide.md" }))).stdout)).toBe("deny");
    expect(decision((await handleCodex("pre-tool-use", pre("shell", { command: ["cat", "docs/guide.md"] }))).stdout)).toBe("deny");
    expect(decision((await handleCodex("pre-tool-use", pre("Bash", { command: "cat docs/guide.md" }))).stdout)).toBe("deny");
    const patch = "*** Begin Patch\n*** Add File: docs/new.md\n+x\n*** End Patch";
    expect(decision((await handleCodex("pre-tool-use", pre("apply_patch", { command: patch }))).stdout)).toBe("deny");
    expect((await handleCodex("pre-tool-use", pre("exec_command", { cmd: "cat src/main.ts" }))).stdout).toBe("");
  });
});

describe("turning secretgate off by saying so", () => {
  it("“désactive secretgate” pauses THIS session, from this very prompt on", async () => {
    const r = await handleClaudeCode("user-prompt-submit", prompt(`désactive secretgate\ndeploy with ${FAKE.githubPat}`));
    const out = JSON.parse(r.stdout);
    expect(out.decision).toBeUndefined(); // the secret-bearing prompt goes through: the user asked
    expect(out.systemMessage).toMatch(/DISABLED for this session only/);
    expect(disableState({ sessionId: "s1" })).toMatchObject({ disabled: true, lifetime: true });
    expect(disableState({ sessionId: "other" }).disabled).toBe(false);
  });

  it("keeps the scope unless asked, and “réactive secretgate” turns it back on", async () => {
    await handleClaudeCode("user-prompt-submit", prompt("désactive secretgate"));
    expect(decision((await handleClaudeCode("pre-tool-use", pre("Read", { file_path: "docs/guide.md" }))).stdout)).toBe("deny");
    const back = await handleClaudeCode("user-prompt-submit", prompt("réactive secretgate"));
    expect(JSON.parse(back.stdout).systemMessage).toMatch(/re-enabled/);
    expect(disableState({ sessionId: "s1" }).disabled).toBe(false);
    await handleClaudeCode("user-prompt-submit", prompt("désactive secretgate et le scope"));
    expect((await handleClaudeCode("pre-tool-use", pre("Read", { file_path: "docs/guide.md" }))).stdout).toBe("{}");
  });

  it("works for Codex too (silently — Codex has no hook message field)", async () => {
    const r = await handleCodex("user-prompt-submit", prompt("disable secretgate"));
    expect(r.stdout).toBe("");
    expect(disableState({ sessionId: "s1" }).disabled).toBe(true);
  });

  it("a discussion about the feature does not trigger it", async () => {
    await handleClaudeCode("user-prompt-submit", prompt("pourquoi désactiver secretgate casse les tests ?"));
    expect(disableState({ sessionId: "s1" }).disabled).toBe(false);
  });
});

describe("tamper guard — the agent cannot quietly switch its own firewall off", () => {
  it("Claude Code asks before `secretgate disable` / edits to secretgate state", async () => {
    rmSync(join(proj, ".secretgate.json"));
    for (const command of ["secretgate disable --forever", "node ~/.secretgate/bin/secretgate.mjs allow --rule github-pat", "npx secretgate uninstall --all"]) {
      expect(decision((await handleClaudeCode("pre-tool-use", pre("Bash", { command }))).stdout)).toBe("ask");
    }
    expect(decision((await handleClaudeCode("pre-tool-use", pre("Write", { file_path: join(home, "disabled.json"), content: "{}" }))).stdout)).toBe("ask");
    expect(decision((await handleClaudeCode("pre-tool-use", pre("Write", { file_path: ".secretgate.json", content: "{}" }))).stdout)).toBe("ask");
    expect((await handleClaudeCode("pre-tool-use", pre("Bash", { command: "secretgate status" }))).stdout).toBe("{}");
    expect((await handleClaudeCode("pre-tool-use", pre("Bash", { command: "secretgate enable" }))).stdout).toBe("{}");
  });

  it("Codex cannot ask from a hook: it refuses and says to run it yourself", async () => {
    rmSync(join(proj, ".secretgate.json"));
    const r = JSON.parse((await handleCodex("pre-tool-use", pre("Bash", { command: "secretgate disable" }))).stdout);
    expect(r.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(r.hookSpecificOutput.permissionDecisionReason).toMatch(/run the command yourself/);
  });
});

describe("audit regressions — sensitive paths", () => {
  beforeEach(() => {
    rmSync(join(proj, ".secretgate.json"));
    writeFileSync(join(proj, ".env"), "K=v\n");
  });

  it("`tests/../.env` is denied even when tests/** is allowlisted", async () => {
    writeFileSync(join(home, "allowlist.json"), JSON.stringify({ paths: ["tests/**"] }));
    expect(decision((await handleClaudeCode("pre-tool-use", pre("Read", { file_path: "tests/../.env" }))).stdout)).toBe("deny");
    expect(decision((await handleClaudeCode("pre-tool-use", pre("Bash", { command: "cat tests/../.env" }))).stdout)).toBe("deny");
  });

  it("a symlink to .env is denied", async () => {
    symlinkSync(join(proj, ".env"), join(proj, "notes.txt"));
    expect(decision((await handleClaudeCode("pre-tool-use", pre("Read", { file_path: "notes.txt" }))).stdout)).toBe("deny");
  });

  it.each([
    "cat<.env",
    "echo $(<.env)",
    "tr a a < .env",
    '"cat" .env',
    "\\cat .env",
    'cat .e""nv',
    "FOO=1 cat .env",
    "sudo cat .env",
    "(cat .env)",
    "{ cat .env; }",
    "sort .env",
    "jq . credentials.json",
    "git show HEAD:.env",
    "cat .en?",
    "cp .env x && cat x",
    "source .env && env",
  ])("Bash bypass closed: %s", async (command) => {
    expect(decision((await handleClaudeCode("pre-tool-use", pre("Bash", { command }))).stdout)).toBe("deny");
  });

  it("writing or listing .env is still fine (restore flow)", async () => {
    expect((await handleClaudeCode("pre-tool-use", pre("Bash", { command: "echo K=v > .env" }))).stdout).toBe("{}");
    expect((await handleClaudeCode("pre-tool-use", pre("Bash", { command: "ls -la .env" }))).stdout).toBe("{}");
  });

  it("Grep with a glob naming sensitive files, and MCP readers, are denied", async () => {
    expect(decision((await handleClaudeCode("pre-tool-use", pre("Grep", { pattern: ".", glob: ".env*", output_mode: "content" }))).stdout)).toBe("deny");
    expect(decision((await handleClaudeCode("pre-tool-use", pre("mcp__filesystem__read_file", { path: join(proj, ".env") }))).stdout)).toBe("deny");
  });

  it.each([".envrc", ".git-credentials", ".pgpass", ".pypirc", "cert.p12", "terraform.tfstate", ".dev.vars"])("%s is sensitive", async (f) => {
    expect(decision((await handleClaudeCode("pre-tool-use", pre("Read", { file_path: f }))).stdout)).toBe("deny");
  });

  it("the secretgate vault itself is sensitive", async () => {
    expect(decision((await handleClaudeCode("pre-tool-use", pre("Read", { file_path: join(home, "vault.json") }))).stdout)).toBe("deny");
  });
});

describe("audit regressions — output and prompts", () => {
  it("an inline `gitleaks:allow` pragma in tool output does not exempt it", async () => {
    const r = await handleClaudeCode("post-tool-use", post("Bash", { command: "curl x" }, `TOKEN=${FAKE.githubPat} gitleaks:allow`));
    expect(r.stdout).not.toContain(FAKE.githubPat);
    expect(r.stdout).toMatch(/SECRETGATE_/);
  });

  it("an untrusted project allowlist cannot switch detection off", async () => {
    writeFileSync(join(proj, ".secretgate.json"), JSON.stringify({ allowlist: { rules: ["github-pat"], paths: ["**"] } }));
    expect(JSON.parse((await handleClaudeCode("user-prompt-submit", prompt(`use ${FAKE.githubPat}`))).stdout).decision).toBe("block");
    writeFileSync(join(proj, ".env"), "K=v\n");
    expect(decision((await handleClaudeCode("pre-tool-use", pre("Read", { file_path: ".env" }))).stdout)).toBe("deny");
  });

  it("an unwritable state directory still fails CLOSED on an unknown output shape", async () => {
    const file = join(home, "not-a-dir");
    writeFileSync(file, "x");
    process.env.SECRETGATE_HOME = join(file, "home");
    const r = await handleClaudeCode("post-tool-use", post("WebFetch", { url: "x" }, { weird: `${FAKE.githubPat}` }));
    expect(r.stdout).not.toBe("");
    expect(r.stdout).not.toContain(FAKE.githubPat);
  });

  it("the URL-credentials rule stays linear on adversarial input", async () => {
    const t = performance.now();
    await handleClaudeCode("post-tool-use", post("Bash", { command: "x" }, `x://${"a.".repeat(80000)}`));
    expect(performance.now() - t).toBeLessThan(1500);
  });
});
