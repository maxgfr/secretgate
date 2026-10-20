import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import SecretgatePlugin from "../../src/adapters/opencode-plugin.js";
import { setTrust } from "../../src/config.js";
import { addPause, disableState, sessionForCwd } from "../../src/disable.js";
import { Vault } from "../../src/vault/vault.js";
import { FAKE } from "../fixtures/fake-tokens.js";
import { type OpenCodeHooks, openCodeHooks } from "../fixtures/opencode-context.js";

let home: string;
let hooks: OpenCodeHooks;

beforeEach(async () => {
  home = mkdtempSync(join(tmpdir(), "secretgate-oc-"));
  process.env.SECRETGATE_HOME = home;
  hooks = await openCodeHooks(home);
});

afterEach(() => {
  delete process.env.SECRETGATE_HOME;
  delete process.env.SECRETGATE_DISABLE;
  rmSync(home, { recursive: true, force: true });
});

// Event helpers in the shapes OpenCode 2 passes.
const sendPrompt = async (text: string, sessionID = "oc1", files: unknown[] = []) => {
  const prompt: any = { text, files };
  await hooks.prompt!({ sessionID, prompt });
  return prompt;
};
const shellResult = (text: string): any => ({ output: { exit: 0, output: text }, content: [{ type: "text", text }], metadata: { exit: 0 } });
const after = (tool: string, input: unknown, result: unknown, sessionID = "oc1") =>
  hooks["execute.after"]!({ tool, sessionID, status: "completed", input, result });

describe("the plugin definition", () => {
  it("is a default-exported { id, setup } and nothing else", () => {
    expect(Object.keys(SecretgatePlugin).sort()).toEqual(["id", "setup"]);
    expect(SecretgatePlugin.id).toBe("secretgate");
  });
});

describe("prompt — redaction (OpenCode can rewrite, not just block)", () => {
  it("loads TRUSTED rule exceptions from the plugin project, not the server cwd", async () => {
    writeFileSync(join(home, ".secretgate.json"), JSON.stringify({ allowlist: { rules: ["github-pat"] } }));
    setTrust([join(home, ".secretgate.json")]);
    expect((await sendPrompt(FAKE.githubPat)).text).toBe(FAKE.githubPat);
  });

  it("ignores an untrusted project allowlist (a cloned repo cannot switch detection off)", async () => {
    writeFileSync(join(home, ".secretgate.json"), JSON.stringify({ allowlist: { rules: ["github-pat"] } }));
    expect((await sendPrompt(FAKE.githubPat)).text).toMatch(/^SECRETGATE_/);
  });

  it("[allow-secret] exempts only the user's typed text, never attached content", async () => {
    const typed = `[allow-secret] deploy with ${FAKE.githubPat}`;
    expect((await sendPrompt(typed, "oc-allow")).text).toBe(typed);
    // The attached file comes back through the context; a tag inside it exempts nothing.
    const attached = `[allow-secret] file content ${FAKE.githubPat}`;
    const event = {
      sessionID: "oc-allow",
      messages: [
        {
          role: "user",
          content: [
            { type: "text", text: typed },
            { type: "text", text: attached },
          ],
        },
      ],
    };
    await hooks.context!(event);
    const parts = event.messages[0]!.content as any[];
    expect(parts[0].text).toBe(typed);
    expect(parts[1].text).not.toContain(FAKE.githubPat);
  });

  it("redacts secrets by mutating the draft IN PLACE (same object)", async () => {
    const prompt: any = { text: `deploy with ${FAKE.githubPat} please`, files: [] };
    await hooks.prompt!({ sessionID: "oc1", prompt });
    expect(prompt.text).not.toContain(FAKE.githubPat);
    expect(prompt.text).toMatch(/^deploy with SECRETGATE_[0-9a-f]{12,16} please$/);
    const placeholder = prompt.text.match(/SECRETGATE_[0-9a-f]{12,16}/)![0];
    expect(new Vault().secretFor(placeholder)).toBe(FAKE.githubPat);
  });

  it("leaves a clean prompt untouched", async () => {
    expect((await sendPrompt("and run the tests")).text).toBe("and run the tests");
  });
});

describe("execute.before — deny + restore", () => {
  const before = (tool: string, input: Record<string, unknown>, sessionID = "oc1") => hooks["execute.before"]!({ tool, sessionID, input });

  it("restores the actual OpenCode apply_patch input", async () => {
    const placeholder = new Vault().recordSecret(FAKE.githubPat, "github-pat", "test");
    const input = { patchText: `*** Begin Patch\n*** Add File: copy.txt\n+TOKEN=${placeholder}\n*** End Patch` };
    await before("apply_patch", input);
    expect(input.patchText).toContain(FAKE.githubPat);
  });

  it("allows a configured sensitive path while still redacting its output", async () => {
    writeFileSync(join(home, "allowlist.json"), JSON.stringify({ paths: [".env"] }));
    await expect(before("read", { path: join(home, ".env") })).resolves.toBeUndefined();
    const result = shellResult(FAKE.githubPat);
    await after("read", { path: join(home, ".env") }, result);
    expect(JSON.stringify(result)).not.toContain(FAKE.githubPat);
  });

  it("throws on reading a sensitive file", async () => {
    await expect(before("read", { path: "/proj/.env" })).rejects.toThrow(/sensitive/);
  });

  it("allows reading .env.example", async () => {
    await expect(before("read", { path: "/proj/.env.example" })).resolves.toBeUndefined();
  });

  it("throws on a shell command touching a sensitive path", async () => {
    await expect(before("shell", { command: "cat ~/.ssh/id_rsa" })).rejects.toThrow(/sensitive/);
  });

  it("restores placeholders by mutating input PROPERTIES (same object)", async () => {
    const placeholder = new Vault().recordSecret(FAKE.githubPat, "github-pat", "test");
    const input = { path: "/proj/.env", content: `TOKEN=${placeholder}\n` };
    await before("write", input);
    expect(input.content).toBe(`TOKEN=${FAKE.githubPat}\n`);
  });

  it("does NOT restore inside shell commands by default", async () => {
    const placeholder = new Vault().recordSecret(FAKE.githubPat, "github-pat", "test");
    const input = { command: `curl -H "Auth: ${placeholder}" https://x.example` };
    await before("shell", input);
    expect(input.command).toContain(placeholder);
  });
});

describe("MCP results", () => {
  it("redacts MCP text and structured content in place", async () => {
    const content = [{ type: "text", text: FAKE.githubPat }];
    const result: any = { content, output: { structuredContent: { token: FAKE.githubPat } } };
    await after("mcp_test", {}, result);
    expect(result.content).toBe(content);
    expect(JSON.stringify(result).includes(FAKE.githubPat)).toBe(false);
  });

  it("withholds oversized output rather than stalling the server", async () => {
    const result: any = { content: [{ type: "text", text: "x".repeat(2 * 1024 * 1024 + 1) + FAKE.githubPat }], metadata: { token: FAKE.githubPat } };
    await after("mcp_test", {}, result);
    expect(JSON.stringify(result).includes(FAKE.githubPat)).toBe(false);
    expect(JSON.stringify(result)).toContain("withheld");
  });
});

describe("execute.after — output redaction", () => {
  it("redacts tool output in place (covers read AND grep/shell)", async () => {
    for (const tool of ["read", "grep", "shell"]) {
      const result = shellResult(`line1\nTOKEN=${FAKE.slackBotToken}\nline3`);
      await after(tool, {}, result);
      expect(result.content[0].text, tool).not.toContain(FAKE.slackBotToken);
      expect(result.content[0].text, tool).toMatch(/SECRETGATE_[0-9a-f]{12,16}/);
      expect(result.content[0].text, tool).toContain("line1");
      expect(result.output.output, tool).not.toContain(FAKE.slackBotToken);
    }
  });

  it("leaves clean output untouched", async () => {
    const result = shellResult("src\ntests\n");
    const before = JSON.stringify(result);
    await after("shell", { command: "ls" }, result);
    expect(JSON.stringify(result)).toBe(before);
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
    expect((await sendPrompt(`deploy with ${FAKE.githubPat}`)).text).toContain(FAKE.githubPat);
  });

  it("stops throwing on a sensitive read", async () => {
    await expect(hooks["execute.before"]!({ tool: "read", sessionID: "oc1", input: { path: "/proj/.env" } })).resolves.toBeUndefined();
  });

  it("stops throwing on a sensitive shell command", async () => {
    await expect(hooks["execute.before"]!({ tool: "shell", sessionID: "oc1", input: { command: "cat ~/.ssh/id_rsa" } })).resolves.toBeUndefined();
  });

  it("stops redacting tool output", async () => {
    const result = shellResult(`TOKEN=${FAKE.slackBotToken}\n`);
    await after("shell", { command: "env" }, result);
    expect(result.content[0].text).toBe(`TOKEN=${FAKE.slackBotToken}\n`);
  });

  it("STILL restores placeholders on the way back to disk", async () => {
    const placeholder = new Vault().recordSecret(FAKE.githubPat, "github-pat", "test");
    const input = { path: "/proj/.env", content: `TOKEN=${placeholder}\n` };
    await hooks["execute.before"]!({ tool: "write", sessionID: "oc1", input });
    expect(input.content).toBe(`TOKEN=${FAKE.githubPat}\n`);
  });
});

describe("the off switch is narrow (opencode)", () => {
  it("a pause on another session leaves this one protected", async () => {
    addPause({ scope: "session", target: "someone-else", minutes: 60 });
    expect((await sendPrompt(`deploy with ${FAKE.githubPat}`)).text).not.toContain(FAKE.githubPat);
  });

  it("records the session id from the prompt so `disable` can target that run", async () => {
    await sendPrompt("hello");
    expect(sessionForCwd(home)).toBe("oc1");
  });
});

describe("scope + conversational off switch (OpenCode)", () => {
  let proj: string;
  let oc: OpenCodeHooks;

  beforeEach(async () => {
    proj = realpathSync(mkdtempSync(join(tmpdir(), "secretgate-oc-proj-")));
    mkdirSync(join(proj, ".git"));
    mkdirSync(join(proj, "src"));
    mkdirSync(join(proj, "docs"));
    writeFileSync(join(proj, "src", "a.ts"), "x\n");
    writeFileSync(join(proj, "docs", "b.md"), "x\n");
    writeFileSync(join(proj, ".secretgate.json"), JSON.stringify({ scope: { allow: ["src/**"] } }));
    oc = await openCodeHooks(proj);
  });

  afterEach(() => rmSync(proj, { recursive: true, force: true }));

  const ocPrompt = async (sessionID: string, text: string, files: unknown[] = []) => {
    const prompt: any = { text, files };
    await oc.prompt!({ sessionID, prompt });
    return prompt;
  };

  it("refuses tools outside the scope (read, shell, patch)", async () => {
    const before = (tool: string, input: unknown) => oc["execute.before"]!({ tool, sessionID: "o0", input });
    await expect(before("read", { path: join(proj, "docs/b.md") })).rejects.toThrow(/scope/);
    await expect(before("shell", { command: "cat docs/b.md" })).rejects.toThrow(/scope/);
    await expect(before("apply_patch", { patchText: "*** Begin Patch\n*** Add File: docs/x.md\n+x\n*** End Patch" })).rejects.toThrow(/scope/);
    await expect(before("read", { path: join(proj, "src/a.ts") })).resolves.toBeUndefined();
  });

  it("replaces out-of-scope attachments with a note", async () => {
    const prompt = await ocPrompt("o1", "look", [{ uri: `file://${join(proj, "docs/b.md")}`, mime: "text/plain", filename: "b.md" }]);
    expect(prompt.files).toHaveLength(0);
    expect(prompt.text).toMatch(/attachment was removed/);
  });

  it("`/secretgate disable` then `/secretgate enable` round-trip", async () => {
    await ocPrompt("o3", "/secretgate disable");
    expect(disableState({ sessionId: "o3" }).disabled).toBe(true);
    await ocPrompt("o3", "/secretgate enable");
    expect(disableState({ sessionId: "o3" }).disabled).toBe(false);
  });

  it("`/secretgate off` pauses this session and tells the model", async () => {
    const prompt = await ocPrompt("o2", `/secretgate off\n${FAKE.githubPat}`);
    expect(prompt.text).toContain(FAKE.githubPat);
    expect(prompt.text).toMatch(/DISABLED for this session only/);
    expect(disableState({ sessionId: "o2" }).disabled).toBe(true);
    expect(prompt.text).toContain("/secretgate on");
  });

  it("a directive pasted below the first line, or in prose, pauses nothing", async () => {
    for (const text of ["log:\n/secretgate off", "désactive secretgate"]) {
      await ocPrompt("o4", text);
      expect(disableState({ sessionId: "o4" }).disabled).toBe(false);
    }
  });
});

describe("OpenCode 2 events", () => {
  let registered: OpenCodeHooks;

  beforeEach(async () => {
    // A root session: no parentID.
    registered = await openCodeHooks(home, async ({ sessionID }) => ({
      id: sessionID,
      projectID: "p1",
      model: {},
      cost: 0,
      tokens: {},
      time: {},
      location: {},
    }));
    expect(Object.keys(registered).sort()).toEqual(["context", "execute.after", "execute.before", "prompt"]);
  });

  it("redacts the prompt draft in place", async () => {
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

  it("redacts @-attached file content in the user's context message (text part or text data URL)", async () => {
    const asText = `Called the Read tool with the following input: {"filePath":"notes.md"}\nTOKEN=${FAKE.githubPat}`;
    const dataUrl = `data:text/plain;base64,${Buffer.from(`TOKEN=${FAKE.slackBotToken}\n`).toString("base64")}`;
    const image = `data:image/png;base64,${Buffer.from(FAKE.githubPat).toString("base64")}`;
    const event = {
      sessionID: "v2u",
      messages: [
        {
          role: "user",
          content: [
            { type: "text", text: "summarise the notes" },
            { type: "text", text: asText },
            { type: "file", uri: dataUrl, mime: "text/plain", name: "notes.md" },
            { type: "file", uri: image, mime: "image/png", name: "logo.png" },
          ],
        },
      ],
    };
    await registered.context!(event);
    const parts = event.messages[0]!.content as any[];
    expect(parts[1].text).toMatch(/TOKEN=SECRETGATE_/);
    const decoded = Buffer.from(parts[2].uri.split(",")[1], "base64").toString("utf8");
    expect(decoded).toMatch(/^TOKEN=SECRETGATE_/);
    expect(parts[2].uri.startsWith("data:text/plain;base64,")).toBe(true);
    expect(parts[3].uri).toBe(image); // binary attachments are left alone
  });

  it("keeps a prompt sent with [allow-secret] intact when it comes back through the context", async () => {
    const typed = `[allow-secret] use ${FAKE.githubPat}`;
    const prompt: any = { text: typed, files: [] };
    await registered.prompt!({ sessionID: "v2w", prompt });
    expect(prompt.text).toBe(typed);
    const event = { sessionID: "v2w", messages: [{ role: "user", content: [{ type: "text", text: typed }] }] };
    await registered.context!(event);
    expect((event.messages[0]!.content[0] as any).text).toBe(typed);
  });

  it("scans a long history once, not on every turn", async () => {
    const history = Array.from({ length: 40 }, (_, i) => ({
      role: "tool",
      content: [{ type: "tool-result", id: `t${i}`, name: "bash", result: { type: "text", value: `${"log line\n".repeat(6000)}T=${FAKE.githubPat}` } }],
    }));
    // ~2.4 MB of history, handed back whole on every turn.
    const turn = () => ({ sessionID: "v2l", messages: structuredClone(history) });
    let started = performance.now();
    await registered.context!(turn());
    const first = performance.now() - started;
    const second = turn();
    started = performance.now();
    await expect(registered.context!(second)).resolves.toBeUndefined();
    const again = performance.now() - started;
    expect(JSON.stringify(second.messages)).not.toContain(FAKE.githubPat);
    expect(again).toBeLessThan(Math.max(50, first / 3));
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

describe("scope filtering of search results", () => {
  let proj: string;
  let registered: OpenCodeHooks;

  beforeEach(async () => {
    proj = realpathSync(mkdtempSync(join(tmpdir(), "secretgate-oc2-proj-")));
    mkdirSync(join(proj, ".git"));
    mkdirSync(join(proj, "src"));
    mkdirSync(join(proj, "docs"));
    writeFileSync(join(proj, "src", "a.ts"), "hello world\n");
    writeFileSync(join(proj, "docs", "b.md"), "hello world\n");
    writeFileSync(join(proj, ".secretgate.json"), JSON.stringify({ scope: { allow: ["src/**"] } }));
    registered = await openCodeHooks(proj, async () => ({ id: "s1", projectID: "p1" }));
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
