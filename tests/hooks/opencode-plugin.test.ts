import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SecretgatePlugin } from "../../src/adapters/opencode-plugin.js";
import { setTrust } from "../../src/config.js";
import { addPause, disableState, sessionForCwd } from "../../src/disable.js";
import { Vault } from "../../src/vault/vault.js";
import { FAKE } from "../fixtures/fake-tokens.js";

let home: string;
let hooks: Record<string, (input: any, output: any) => Promise<void>>;

beforeEach(async () => {
  home = mkdtempSync(join(tmpdir(), "secretgate-oc-"));
  process.env.SECRETGATE_HOME = home;
  hooks = (await SecretgatePlugin({ project: {}, directory: home })) as any;
});

afterEach(() => {
  delete process.env.SECRETGATE_HOME;
  delete process.env.SECRETGATE_DISABLE;
  rmSync(home, { recursive: true, force: true });
});

describe("chat.message — prompt redaction (OpenCode can rewrite, not just block)", () => {
  it("loads TRUSTED rule exceptions from the plugin project, not the server cwd", async () => {
    writeFileSync(join(home, ".secretgate.json"), JSON.stringify({ allowlist: { rules: ["github-pat"] } }));
    setTrust([join(home, ".secretgate.json")]);
    const output = { parts: [{ text: FAKE.githubPat }] };
    await hooks["chat.message"]!({}, output);
    expect(output.parts[0]!.text).toBe(FAKE.githubPat);
  });

  it("ignores an untrusted project allowlist (a cloned repo cannot switch detection off)", async () => {
    writeFileSync(join(home, ".secretgate.json"), JSON.stringify({ allowlist: { rules: ["github-pat"] } }));
    const output = { parts: [{ text: FAKE.githubPat }] };
    await hooks["chat.message"]!({}, output);
    expect(output.parts[0]!.text).toMatch(/^SECRETGATE_/);
  });

  it("[allow-secret] exempts only the user's typed text, never attached content", async () => {
    const parts = [
      { type: "text", text: `[allow-secret] deploy with ${FAKE.githubPat}` },
      { type: "text", synthetic: true, text: `file content ${FAKE.githubPat}` },
    ];
    await hooks["chat.message"]!({}, { parts });
    expect(parts[0]!.text).toContain(FAKE.githubPat);
    expect(parts[1]!.text).not.toContain(FAKE.githubPat);
    // …and a tag inside attached content exempts nothing.
    const forged = [
      { type: "text", text: `token ${FAKE.githubPat}` },
      { type: "text", synthetic: true, text: "[allow-secret]" },
    ];
    await hooks["chat.message"]!({}, { parts: forged });
    expect(forged[0]!.text).not.toContain(FAKE.githubPat);
  });
  it("redacts secrets by mutating parts IN PLACE (same objects)", async () => {
    const parts = [
      { type: "text", text: `deploy with ${FAKE.githubPat} please` },
      { type: "text", text: "and run the tests" },
    ];
    const output = { message: { role: "user" }, parts };
    await hooks["chat.message"]!({}, output);
    expect(output.parts).toBe(parts); // same array
    expect(parts[0]!.text).not.toContain(FAKE.githubPat);
    expect(parts[0]!.text).toMatch(/SECRETGATE_[0-9a-f]{12,16}/);
    expect(parts[1]!.text).toBe("and run the tests");
    const placeholder = parts[0]!.text.match(/SECRETGATE_[0-9a-f]{12,16}/)![0];
    expect(new Vault().secretFor(placeholder)).toBe(FAKE.githubPat);
  });

  it("skips redaction when the [allow-secret] tag is present", async () => {
    const parts = [{ type: "text", text: `[allow-secret] use ${FAKE.githubPat}` }];
    await hooks["chat.message"]!({}, { message: {}, parts });
    expect(parts[0]!.text).toContain(FAKE.githubPat);
  });
});

describe("tool.execute.before — deny + restore", () => {
  it("restores the actual OpenCode apply_patch input", async () => {
    const placeholder = new Vault().recordSecret(FAKE.githubPat, "github-pat", "test");
    const args = { patchText: `*** Begin Patch\n*** Add File: copy.txt\n+TOKEN=${placeholder}\n*** End Patch` };
    await hooks["tool.execute.before"]!({ tool: "apply_patch" }, { args });
    expect(args.patchText).toContain(FAKE.githubPat);
  });

  it("allows a configured sensitive path while still redacting its output", async () => {
    writeFileSync(join(home, "allowlist.json"), JSON.stringify({ paths: [".env"] }));
    await expect(hooks["tool.execute.before"]!({ tool: "read" }, { args: { filePath: join(home, ".env") } })).resolves.toBeUndefined();
    const output = { output: FAKE.githubPat };
    await hooks["tool.execute.after"]!({ tool: "read" }, output);
    expect(output.output).not.toContain(FAKE.githubPat);
  });
  it("throws on reading a sensitive file", async () => {
    await expect(hooks["tool.execute.before"]!({ tool: "read" }, { args: { filePath: "/proj/.env" } })).rejects.toThrow(/sensitive/);
  });

  it("allows reading .env.example", async () => {
    await expect(hooks["tool.execute.before"]!({ tool: "read" }, { args: { filePath: "/proj/.env.example" } })).resolves.toBeUndefined();
  });

  it("throws on a bash command touching a sensitive path", async () => {
    await expect(hooks["tool.execute.before"]!({ tool: "bash" }, { args: { command: "cat ~/.ssh/id_rsa" } })).rejects.toThrow(/sensitive/);
  });

  it("restores placeholders by mutating args PROPERTIES (same object)", async () => {
    const placeholder = new Vault().recordSecret(FAKE.githubPat, "github-pat", "test");
    const args = { filePath: "/proj/.env", content: `TOKEN=${placeholder}\n` };
    const output = { args };
    await hooks["tool.execute.before"]!({ tool: "write" }, output);
    expect(output.args).toBe(args); // same object — wholesale replacement is ignored by OpenCode
    expect(args.content).toBe(`TOKEN=${FAKE.githubPat}\n`);
  });

  it("does NOT restore inside bash commands by default", async () => {
    const placeholder = new Vault().recordSecret(FAKE.githubPat, "github-pat", "test");
    const args = { command: `curl -H "Auth: ${placeholder}" https://x.example` };
    await hooks["tool.execute.before"]!({ tool: "bash" }, { args });
    expect(args.command).toContain(placeholder);
  });

  it("restores inside bash when restoreBash is enabled in config", async () => {
    writeFileSync(join(home, "config.json"), JSON.stringify({ restoreBash: true }));
    const placeholder = new Vault().recordSecret(FAKE.githubPat, "github-pat", "test");
    const args = { command: `deploy --token ${placeholder}` };
    await hooks["tool.execute.before"]!({ tool: "bash" }, { args });
    expect(args.command).toBe(`deploy --token ${FAKE.githubPat}`);
  });
});

describe("MCP result contract", () => {
  it("remasks restored arguments in model-bound history, including failed tool calls", async () => {
    const args = { filePath: "copy.txt", content: new Vault().recordSecret(FAKE.githubPat, "github-pat", "test") };
    await hooks["tool.execute.before"]!({ tool: "write" }, { args });
    expect(args.content.includes(FAKE.githubPat)).toBe(true);
    const output = {
      messages: [{ info: { sessionID: "oc1" }, parts: [{ type: "tool", state: { status: "error", input: args, error: `write failed: ${FAKE.githubPat}` } }] }],
    };
    await hooks["experimental.chat.messages.transform"]!({}, output);
    expect(JSON.stringify(output).includes(FAKE.githubPat)).toBe(false);
  });

  it("withholds all fields of a mixed MCP/native result on a scan error", async () => {
    const output = { content: [{ type: "text", text: "x".repeat(2 * 1024 * 1024 + 1) }], output: FAKE.githubPat, metadata: { token: FAKE.githubPat } };
    await hooks["tool.execute.after"]!({ tool: "mcp_test" }, output);
    expect(JSON.stringify(output).includes(FAKE.githubPat)).toBe(false);
  });
  it("redacts MCP text and structured content in place, including error results", async () => {
    const content = [{ type: "text", text: FAKE.githubPat }];
    const output = { content, structuredContent: { token: FAKE.githubPat }, isError: true };
    await hooks["tool.execute.after"]!({ tool: "mcp_test" }, output);
    expect(output.content).toBe(content);
    expect(JSON.stringify(output).includes(FAKE.githubPat)).toBe(false);
    expect(output.isError).toBe(true);
  });

  it("withholds oversized output rather than stalling the server", async () => {
    const output = { content: [{ type: "text", text: "x".repeat(2 * 1024 * 1024 + 1) + FAKE.githubPat }] };
    await hooks["tool.execute.after"]!({ tool: "mcp_test" }, output);
    expect(JSON.stringify(output).includes(FAKE.githubPat)).toBe(false);
    expect(JSON.stringify(output)).toContain("withheld");
  });
});

describe("tool.execute.after — output redaction", () => {
  it("redacts tool output in place (covers read AND grep/glob)", async () => {
    for (const tool of ["read", "grep", "bash"]) {
      const output = { title: "result", output: `line1\nTOKEN=${FAKE.slackBotToken}\nline3`, metadata: { count: 1 } };
      await hooks["tool.execute.after"]!({ tool }, output);
      expect(output.output, tool).not.toContain(FAKE.slackBotToken);
      expect(output.output, tool).toMatch(/SECRETGATE_[0-9a-f]{12,16}/);
      expect(output.output, tool).toContain("line1");
    }
  });

  it("leaves clean output untouched", async () => {
    const output = { title: "ls", output: "src\ntests\n", metadata: {} };
    await hooks["tool.execute.after"]!({ tool: "bash" }, output);
    expect(output.output).toBe("src\ntests\n");
  });
});

// The plugin runs in-process, so it resolves the disable state from the env and
// from process.cwd() rather than from a hook payload.
describe.each([
  ["SECRETGATE_DISABLE=1", () => (process.env.SECRETGATE_DISABLE = "1")],
  ["a session pause", () => addPause({ scope: "session", target: "oc1", minutes: 60 })],
  ["a directory pause", () => addPause({ scope: "path", target: home, minutes: 60 })],
])("disabled by %s", (_label, disable) => {
  beforeEach(() => {
    disable();
  });

  it("stops redacting prompts", async () => {
    const parts = [{ type: "text", text: `deploy with ${FAKE.githubPat}` }];
    await hooks["chat.message"]!({ sessionID: "oc1" }, { message: {}, parts });
    expect(parts[0]!.text).toContain(FAKE.githubPat);
  });

  it("stops throwing on a sensitive read", async () => {
    await expect(hooks["tool.execute.before"]!({ tool: "read", sessionID: "oc1" }, { args: { filePath: "/proj/.env" } })).resolves.toBeUndefined();
  });

  it("stops throwing on a sensitive bash command", async () => {
    await expect(hooks["tool.execute.before"]!({ tool: "bash", sessionID: "oc1" }, { args: { command: "cat ~/.ssh/id_rsa" } })).resolves.toBeUndefined();
  });

  it("stops redacting tool output", async () => {
    const output = { title: "env", output: `TOKEN=${FAKE.slackBotToken}\n`, metadata: {} };
    await hooks["tool.execute.after"]!({ tool: "bash", sessionID: "oc1" }, output);
    expect(output.output).toBe(`TOKEN=${FAKE.slackBotToken}\n`);
  });

  it("STILL restores placeholders on the way back to disk", async () => {
    const placeholder = new Vault().recordSecret(FAKE.githubPat, "github-pat", "test");
    const args = { filePath: "/proj/.env", content: `TOKEN=${placeholder}\n` };
    await hooks["tool.execute.before"]!({ tool: "write", sessionID: "oc1" }, { args });
    expect(args.content).toBe(`TOKEN=${FAKE.githubPat}\n`);
  });
});

describe("the off switch is narrow (opencode)", () => {
  it("a pause on another session leaves this one protected", async () => {
    addPause({ scope: "session", target: "someone-else", minutes: 60 });
    const parts = [{ type: "text", text: `deploy with ${FAKE.githubPat}` }];
    await hooks["chat.message"]!({ sessionID: "oc1" }, { message: {}, parts });
    expect(parts[0]!.text).not.toContain(FAKE.githubPat);
  });

  it("records the session id from chat.message so `disable` can target that run", async () => {
    await hooks["chat.message"]!({ sessionID: "oc1" }, { message: {}, parts: [{ type: "text", text: "hello" }] });
    expect(sessionForCwd(home)).toBe("oc1");
  });
});

describe("scope + conversational off switch (OpenCode)", () => {
  let proj: string;
  let oc: Record<string, (input: any, output: any) => Promise<void>>;

  beforeEach(async () => {
    proj = realpathSync(mkdtempSync(join(tmpdir(), "secretgate-oc-proj-")));
    mkdirSync(join(proj, ".git"));
    mkdirSync(join(proj, "src"));
    mkdirSync(join(proj, "docs"));
    writeFileSync(join(proj, "src", "a.ts"), "x\n");
    writeFileSync(join(proj, "docs", "b.md"), "x\n");
    writeFileSync(join(proj, ".secretgate.json"), JSON.stringify({ scope: { allow: ["src/**"] } }));
    // A real OpenCode passes its client; every session here is top-level.
    const client = { session: { get: async () => ({ data: {} }) } };
    oc = (await SecretgatePlugin({ directory: proj, client })) as any;
  });

  afterEach(() => rmSync(proj, { recursive: true, force: true }));

  it("refuses tools outside the scope (read, bash, patch)", async () => {
    await expect(oc["tool.execute.before"]!({ tool: "read" }, { args: { filePath: join(proj, "docs/b.md") } })).rejects.toThrow(/scope/);
    await expect(oc["tool.execute.before"]!({ tool: "bash" }, { args: { command: "cat docs/b.md" } })).rejects.toThrow(/scope/);
    await expect(
      oc["tool.execute.before"]!({ tool: "apply_patch" }, { args: { patchText: "*** Begin Patch\n*** Add File: docs/x.md\n+x\n*** End Patch" } }),
    ).rejects.toThrow(/scope/);
    await expect(oc["tool.execute.before"]!({ tool: "read" }, { args: { filePath: join(proj, "src/a.ts") } })).resolves.toBeUndefined();
  });

  it("filters glob/grep output and replaces out-of-scope attachments", async () => {
    const out = { output: `${join(proj, "src/a.ts")}\n${join(proj, "docs/b.md")}`, title: "", metadata: {} };
    await oc["tool.execute.after"]!({ tool: "glob", args: { pattern: "**/*" } }, out);
    expect(out.output).toBe(join(proj, "src/a.ts"));
    const parts: any[] = [{ type: "file", url: `file://${join(proj, "docs/b.md")}`, mime: "text/plain", filename: "b.md" }];
    await oc["chat.message"]!({ sessionID: "o1" }, { parts });
    expect(parts[0].type).toBe("text");
    expect(parts[0].text).toMatch(/attachment was removed/);
    expect(parts[0].url).toBeUndefined();
  });

  it("`/secretgate disable` then `/secretgate enable` round-trip", async () => {
    await oc["chat.message"]!({ sessionID: "o3" }, { parts: [{ type: "text", text: "/secretgate disable" }] });
    expect(disableState({ sessionId: "o3" }).disabled).toBe(true);
    await oc["chat.message"]!({ sessionID: "o3" }, { parts: [{ type: "text", text: "/secretgate enable" }] });
    expect(disableState({ sessionId: "o3" }).disabled).toBe(false);
  });

  it("“désactive secretgate” pauses this session and tells the model", async () => {
    const parts: any[] = [{ type: "text", text: `désactive secretgate\n${FAKE.githubPat}` }];
    await oc["chat.message"]!({ sessionID: "o2" }, { parts });
    expect(parts[0].text).toContain(FAKE.githubPat);
    expect(parts[0].text).toMatch(/DISABLED for this session only/);
    expect(disableState({ sessionId: "o2" }).disabled).toBe(true);
  });
});
