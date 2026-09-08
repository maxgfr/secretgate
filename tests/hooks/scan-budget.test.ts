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

it("does not exempt arbitrary base64 keys or text data URLs", () => {
  const output = { base64: FAKE.awsKeyId, url: `data:text/plain,${FAKE.githubPat}` };
  const result = mapStrings(output, eventRedactor(new Vault(), "test", {}), isBinaryField).value;
  expect(JSON.stringify(result).includes(FAKE.awsKeyId)).toBe(false);
  expect(JSON.stringify(result).includes(FAKE.githubPat)).toBe(false);
});
