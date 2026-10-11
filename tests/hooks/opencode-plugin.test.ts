import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import SecretgatePlugin from "../../src/adapters/opencode-plugin.js";
import { setTrust } from "../../src/config.js";
import { addPause, disableState, sessionForCwd } from "../../src/disable.js";
import { Vault } from "../../src/vault/vault.js";
import { FAKE } from "../fixtures/fake-tokens.js";

let home: string;
let hooks: Record<string, (input: any, output: any) => Promise<void>>;

beforeEach(async () => {
  home = mkdtempSync(join(tmpdir(), "secretgate-oc-"));
  process.env.SECRETGATE_HOME = home;
  hooks = (await SecretgatePlugin.server({ project: {}, directory: home })) as any;
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
    oc = (await SecretgatePlugin.server({ directory: proj, client })) as any;
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

  it("restates the grep match count in the output text and metadata", async () => {
    const out = {
      output: `Found 2 matches\n${join(proj, "src/a.ts")}:\n  Line 1: x\n\n${join(proj, "docs/b.md")}:\n  Line 1: x`,
      title: "x",
      metadata: { matches: 2, truncated: false },
    };
    await oc["tool.execute.after"]!({ tool: "grep", args: { pattern: "x" } }, out);
    expect(out.output).toBe(`Found 1 matches\n${join(proj, "src/a.ts")}:\n  Line 1: x\n`);
    expect(out.metadata).toEqual({ matches: 1, truncated: false });
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

// OpenCode 2 registers hooks through the plugin context; a stub context lets
// these tests drive exactly the callbacks OpenCode would invoke.
describe("OpenCode 2 setup — adapted events", () => {
  let registered: Record<string, (event: any) => Promise<void>>;

  beforeEach(async () => {
    registered = {};
    const ctx = {
      location: { directory: home, project: { id: "p1", directory: home, canonical: home } },
      session: {
        hook: async (name: string, callback: (event: any) => Promise<void>) => {
          registered[name] = callback;
        },
        // A root session: no parentID.
        get: async ({ sessionID }: { sessionID: string }) => ({ id: sessionID, projectID: "p1", model: {}, cost: 0, tokens: {}, time: {}, location: {} }),
      },
      tool: {
        hook: async (name: string, callback: (event: any) => Promise<void>) => {
          registered[name] = callback;
        },
      },
    };
    await SecretgatePlugin.setup(ctx as any);
    expect(Object.keys(registered).sort()).toEqual(["context", "execute.after", "execute.before", "prompt"]);
  });

  it("redacts the prompt draft in place, like chat.message did", async () => {
    const prompt: any = { text: `deploy with ${FAKE.githubPat} please`, files: [] };
    await registered.prompt!({ sessionID: "v2a", messageID: "m1", prompt, delivery: "steer" });
    expect(prompt.text).not.toContain(FAKE.githubPat);
    expect(prompt.text).toMatch(/SECRETGATE_[0-9a-f]{12,16}/);
    const placeholder = prompt.text.match(/SECRETGATE_[0-9a-f]{12,16}/)![0];
    expect(new Vault().secretFor(placeholder)).toBe(FAKE.githubPat);
  });

  it("drops sensitive attachments from the draft and notes the removal", async () => {
    writeFileSync(join(home, ".env"), "TOKEN=1\n");
    const prompt: any = { text: "please read this", files: [{ uri: `file://${home}/.env`, mention: 7 }] };
    await registered.prompt!({ sessionID: "v2b", prompt });
    expect(prompt.files).toHaveLength(0);
    expect(prompt.text).toMatch(/attachment was removed/);
  });

  it("drops @mention offsets when the text is rewritten (they no longer match)", async () => {
    const prompt: any = { text: `run ${FAKE.githubPat}`, files: [{ uri: `file://${home}/notes.md`, mention: 4 }] };
    writeFileSync(join(home, "notes.md"), "safe\n");
    await registered.prompt!({ sessionID: "v2c", prompt });
    expect(prompt.files).toHaveLength(1);
    expect("mention" in prompt.files[0]).toBe(false);
  });

  // OpenCode 2.0.26 hands AI-SDK messages: content parts, no per-message info.
  const contextEvent = (sessionID: string, input: Record<string, unknown>, value: string) => ({
    sessionID,
    model: {},
    system: [],
    options: {},
    agent: "build",
    tools: {},
    messages: [
      { id: "m1", role: "user", content: [{ type: "text", text: "copy the token" }], metadata: {} },
      {
        id: "m2",
        role: "assistant",
        content: [
          { type: "text", text: "Reading it." },
          { type: "tool-call", id: "toolu_1", name: "write", input, providerExecuted: false },
        ],
      },
      { role: "tool", content: [{ type: "tool-result", id: "toolu_1", name: "write", result: { type: "text", value }, providerExecuted: false }] },
    ],
  });

  it("redacts tool-call input and tool-result values in the context messages, in place", async () => {
    const input = { path: "copy.txt", content: new Vault().recordSecret(FAKE.githubPat, "github-pat", "test") };
    await registered["execute.before"]!({ tool: "write", sessionID: "v2d", agent: "build", messageID: "m2", id: "toolu_1", input });
    expect(input.content).toBe(FAKE.githubPat);
    const event = contextEvent("v2d", input, `write failed: ${FAKE.githubPat}`);
    const call = event.messages[1]!.content[1] as any;
    const toolResult = event.messages[2]!.content[0] as any;
    await registered.context!(event);
    expect(JSON.stringify(event.messages).includes(FAKE.githubPat)).toBe(false);
    expect(call.input).toBe(input); // same objects — the host keeps its references
    expect(input.content).toMatch(/^SECRETGATE_/);
    expect(toolResult.result.value).toMatch(/^write failed: SECRETGATE_/);
    // A paused session's history is left alone.
    addPause({ scope: "session", target: "v2off", minutes: 60 });
    const paused = contextEvent("v2off", { path: "copy.txt", content: FAKE.githubPat }, FAKE.githubPat);
    await registered.context!(paused);
    expect(JSON.stringify(paused.messages)).toContain(FAKE.githubPat);
  });

  it("refuses reading .env through the real read input ({path})", async () => {
    await expect(registered["execute.before"]!({ tool: "read", sessionID: "v2e", input: { path: ".env" } })).rejects.toThrow(/sensitive/);
    await expect(registered["execute.before"]!({ tool: "shell", sessionID: "v2e", input: { command: "cat ~/.ssh/id_rsa" } })).rejects.toThrow(/sensitive/);
  });

  it("redacts a shell result's content and structured output; failures pass untouched", async () => {
    const leak = `TOKEN=${FAKE.slackBotToken}\n`;
    const result: any = {
      output: { exit: 0, truncated: false, output: leak, status: "completed" },
      content: [{ type: "text", text: leak }],
      metadata: { status: "completed", truncated: false, exit: 0 },
    };
    const content = result.content;
    await registered["execute.after"]!({ tool: "shell", sessionID: "v2e", status: "completed", input: { command: "cat x" }, result });
    expect(result.content).toBe(content);
    expect(result.content[0].text).toMatch(/^TOKEN=SECRETGATE_/);
    expect(result.output.output).toMatch(/^TOKEN=SECRETGATE_/);
    expect(result.output.exit).toBe(0);
    const failed: any = { output: { output: leak }, content: [{ type: "text", text: leak }] };
    await registered["execute.after"]!({ tool: "shell", sessionID: "v2e", status: "error", input: { command: "cat x" }, result: failed });
    expect(failed.content[0].text).toContain(FAKE.slackBotToken);
  });

  it("withholds an unscannable result with a notice the model reads, dropping the structured output", async () => {
    const big = "x".repeat(2 * 1024 * 1024 + 1) + FAKE.githubPat;
    const result: any = { output: { exit: 0, output: big }, content: [{ type: "text", text: big }], metadata: { exit: 0 } };
    await registered["execute.after"]!({ tool: "shell", sessionID: "v2e", status: "completed", input: { command: "cat big" }, result });
    expect(JSON.stringify(result).includes(FAKE.githubPat)).toBe(false);
    expect(result.content).toEqual([{ type: "text", text: expect.stringMatching(/withheld/) }]);
    expect(result.output).toEqual({});
    expect(result.metadata).toEqual({});
    // The structured output keeps its type; only a string output carries the notice.
    const listing: any = { output: [{ path: big }], content: [{ type: "text", text: big }] };
    await registered["execute.after"]!({ tool: "glob", sessionID: "v2e", status: "completed", input: { pattern: "**/*" }, result: listing });
    expect(listing.output).toEqual([]);
    const text: any = { output: big, content: [{ type: "text", text: big }] };
    await registered["execute.after"]!({ tool: "shell", sessionID: "v2e", status: "completed", input: { command: "cat big" }, result: text });
    expect(text.output).toMatch(/withheld/);
  });

  it("fails closed on a completed result that is not an object", async () => {
    await expect(
      registered["execute.after"]!({ tool: "shell", sessionID: "v2e", status: "completed", input: { command: "cat x" }, result: "raw" }),
    ).rejects.toThrow(/withheld/);
  });

  // Real OpenCode 2.0.26 shapes for `read` of a PNG.
  it("passes a base64 image read through untouched, in the result and in later context", async () => {
    const base64 = `iVBORw0K${"A".repeat(2 * 1024 * 1024)}`;
    const imageParts = () => [
      { type: "text", text: "Image read successfully" },
      { type: "file", uri: `data:image/png;base64,${base64}`, mime: "image/png", name: "img.png" },
    ];
    const result: any = {
      output: { type: "file", uri: `file://${home}/img.png`, name: "img.png", content: base64, encoding: "base64", mime: "image/png" },
      content: imageParts(),
      metadata: { truncated: false },
    };
    const before = JSON.stringify(result);
    await registered["execute.after"]!({ tool: "read", sessionID: "v2i", status: "completed", input: { path: "img.png" }, result });
    expect(JSON.stringify(result) === before).toBe(true);
    const event = {
      sessionID: "v2i",
      messages: [{ role: "tool", content: [{ type: "tool-result", id: "t1", name: "read", result: { type: "content", value: imageParts() } }] }],
    };
    await expect(registered.context!(event)).resolves.toBeUndefined();
    // A text file read (utf8) is still scanned.
    const textRead: any = {
      output: { type: "file", uri: `file://${home}/a.txt`, name: "a.txt", content: `TOKEN=${FAKE.githubPat}`, encoding: "utf8", mime: "text/plain" },
      content: [{ type: "text", text: "read" }],
    };
    await registered["execute.after"]!({ tool: "read", sessionID: "v2i", status: "completed", input: { path: "a.txt" }, result: textRead });
    expect(textRead.output.content).toMatch(/^TOKEN=SECRETGATE_/);
  });

  it("restores placeholders in the real write input ({path, content})", async () => {
    const placeholder = new Vault().recordSecret(FAKE.githubPat, "github-pat", "test");
    const input = { path: "out.txt", content: `TOKEN=${placeholder}\n` };
    await registered["execute.before"]!({ tool: "write", sessionID: "v2f", input });
    expect(input.content).toBe(`TOKEN=${FAKE.githubPat}\n`);
  });

  it("restores inside the `shell` tool when restoreBash is enabled", async () => {
    writeFileSync(join(home, "config.json"), JSON.stringify({ restoreBash: true }));
    const placeholder = new Vault().recordSecret(FAKE.githubPat, "github-pat", "test");
    const input = { command: `deploy --token ${placeholder}` };
    await registered["execute.before"]!({ tool: "shell", sessionID: "v2g", input });
    expect(input.command).toBe(`deploy --token ${FAKE.githubPat}`);
  });
});

describe("OpenCode 2 setup — scope filtering of search results", () => {
  let proj: string;
  let registered: Record<string, (event: any) => Promise<void>>;

  beforeEach(async () => {
    proj = realpathSync(mkdtempSync(join(tmpdir(), "secretgate-oc2-proj-")));
    mkdirSync(join(proj, ".git"));
    mkdirSync(join(proj, "src"));
    mkdirSync(join(proj, "docs"));
    writeFileSync(join(proj, "src", "a.ts"), "hello world\n");
    writeFileSync(join(proj, "docs", "b.md"), "hello world\n");
    writeFileSync(join(proj, ".secretgate.json"), JSON.stringify({ scope: { allow: ["src/**"] } }));
    registered = {};
    const hook = async (name: string, callback: (event: any) => Promise<void>) => {
      registered[name] = callback;
    };
    const ctx = {
      location: { directory: proj, project: { id: "p1", directory: proj, canonical: proj } },
      session: { hook, get: async () => ({ id: "s1", projectID: "p1" }) },
      tool: { hook },
    };
    await SecretgatePlugin.setup(ctx as any);
  });

  afterEach(() => rmSync(proj, { recursive: true, force: true }));

  it("drops out-of-scope grep matches from the content text and the output array", async () => {
    const match = (path: string) => ({ entry: { path, type: "file" }, line: 1, offset: 0, text: "hello world\n", submatches: [] });
    const result: any = {
      output: [match("src/a.ts"), match("docs/b.md")],
      content: [
        { type: "text", text: `Found 2 matches\n${join(proj, "src/a.ts")}:\n  Line 1: hello world\n\n${join(proj, "docs/b.md")}:\n  Line 1: hello world\n` },
      ],
      metadata: { matches: 2, truncated: false },
    };
    await registered["execute.after"]!({ tool: "grep", sessionID: "s1", status: "completed", input: { pattern: "hello" }, result });
    expect(result.output.map((m: any) => m.entry.path)).toEqual(["src/a.ts"]);
    expect(result.content[0].text).toContain(join(proj, "src/a.ts"));
    expect(result.content[0].text).not.toContain("docs/b.md");
    // The counts must not reveal that an out-of-scope match existed.
    expect(result.content[0].text).toMatch(/^Found 1 matches\n/);
    expect(result.metadata).toEqual({ matches: 1, truncated: false });
  });

  it("drops out-of-scope glob entries from the content text and the output array", async () => {
    const result: any = {
      output: [
        { path: "src/a.ts", type: "file" },
        { path: "docs/b.md", type: "file" },
      ],
      content: [{ type: "text", text: `${join(proj, "src/a.ts")}\n${join(proj, "docs/b.md")}` }],
      metadata: { count: 2, truncated: false },
    };
    await registered["execute.after"]!({ tool: "glob", sessionID: "s1", status: "completed", input: { pattern: "**/*" }, result });
    expect(result.output).toEqual([{ path: "src/a.ts", type: "file" }]);
    expect(result.content[0].text).toBe(join(proj, "src/a.ts"));
    expect(result.metadata).toEqual({ count: 1, truncated: false });
  });
});
