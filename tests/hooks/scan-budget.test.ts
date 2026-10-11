import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, expect, it } from "vitest";
import { eventRedactor, isBinaryField, SCAN_CAP } from "../../src/hooks/scan-budget.js";
import { mapStrings } from "../../src/hooks/walk.js";
import { Vault } from "../../src/vault/vault.js";
import { FAKE } from "../fixtures/fake-tokens.js";

let home: string;
beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "secretgate-budget-"));
  process.env.SECRETGATE_HOME = home;
});
afterEach(() => {
  delete process.env.SECRETGATE_HOME;
  rmSync(home, { recursive: true, force: true });
});

it("shares the text budget across individually small MCP blocks", () => {
  const content = Array.from({ length: 3 }, () => ({ type: "text", text: "x".repeat(SCAN_CAP / 2) }));
  expect(() => mapStrings({ content }, eventRedactor(new Vault(), "test", {}), isBinaryField)).toThrow("scan budget exceeded");
});

it("preserves large image data while redacting adjacent MCP text", () => {
  const data = "A".repeat(SCAN_CAP + 1);
  const output = {
    content: [
      { type: "image", data },
      { type: "text", text: FAKE.githubPat },
    ],
  };
  const result = mapStrings(output, eventRedactor(new Vault(), "test", {}), isBinaryField).value as typeof output;
  expect(result.content[0]!.data === data).toBe(true);
  expect(JSON.stringify(result).includes(FAKE.githubPat)).toBe(false);
  expect(result.content[1]!.text).toMatch(/^SECRETGATE_/);
});

it("preserves OpenCode 2 image reads: base64 `content` and `data:` uris", () => {
  const base64 = "A".repeat(SCAN_CAP + 1);
  const output = {
    output: { type: "file", content: base64, encoding: "base64", mime: "image/png" },
    content: [{ type: "file", uri: `data:image/png;base64,${base64}`, mime: "image/png" }],
  };
  const result = mapStrings(output, eventRedactor(new Vault(), "test", {}), isBinaryField).value as typeof output;
  expect(result.output.content === base64).toBe(true);
  expect(result.content[0]!.uri === output.content[0]!.uri).toBe(true);
});

it("still scans utf8 or non-image `content` and text data uris", () => {
  const output = {
    utf8: { content: FAKE.githubPat, encoding: "utf8", mime: "image/png" },
    text: { content: FAKE.awsKeyId, encoding: "base64", mime: "text/plain" },
    uri: `data:text/plain,${FAKE.slackBotToken}`,
  };
  const result = JSON.stringify(mapStrings(output, eventRedactor(new Vault(), "test", {}), isBinaryField).value);
  for (const token of [FAKE.githubPat, FAKE.awsKeyId, FAKE.slackBotToken]) expect(result.includes(token)).toBe(false);
});

it("does not exempt arbitrary base64 keys or text data URLs", () => {
  const output = { base64: FAKE.awsKeyId, url: `data:text/plain,${FAKE.githubPat}` };
  const result = mapStrings(output, eventRedactor(new Vault(), "test", {}), isBinaryField).value;
  expect(JSON.stringify(result).includes(FAKE.awsKeyId)).toBe(false);
  expect(JSON.stringify(result).includes(FAKE.githubPat)).toBe(false);
});
