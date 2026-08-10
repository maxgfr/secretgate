import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SecretgatePlugin } from "../../src/adapters/opencode-plugin.js";
import { addPause, sessionForCwd } from "../../src/disable.js";
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
  ["a directory pause", () => addPause({ scope: "path", target: process.cwd(), minutes: 60 })],
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
    expect(sessionForCwd(process.cwd())).toBe("oc1");
  });
});
