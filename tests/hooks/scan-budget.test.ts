import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, expect, it } from "vitest";
import { eventRedactor, isAttachmentPayload, isBinaryField, SCAN_CAP } from "../../src/hooks/scan-budget.js";
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

// The first bytes of real files, then filler: what an attachment looks like.
const PNG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0x0d]);
const payload = (head: Buffer, bytes = (SCAN_CAP * 3) / 4 + 300) => Buffer.concat([head, Buffer.alloc(bytes, 0x41)]).toString("base64");

it("preserves large image data while redacting adjacent MCP text", () => {
  const data = payload(PNG);
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
  const base64 = payload(PNG);
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

// The fields above are skipped for what they HOLD, not for what they are
// called: on any tool, `{type: "image", data: …}` used to be skipped unread.
it("scans an image or audio field that does not hold one", () => {
  const awsSecret = "wJalrXUtnFEMI" + "/K7MDENG/" + "bPxRfiCYzQ9kT4mB2xLp";
  const output = {
    structuredContent: { att: { type: "image", base64: `AWS ${FAKE.awsKeyId} ${awsSecret}` } },
    content: [
      { type: "image", data: `token ${FAKE.githubPat}`, mimeType: "image/png" },
      { type: "audio", data: FAKE.slackBotToken, mimeType: "audio/wav" },
      { type: "file", uri: `data:image/png;base64,key ${FAKE.groqKey}`, mime: "image/png" },
      { type: "file", url: `data:image/png,${FAKE.anthropicKey}` },
    ],
    read: { content: `k ${FAKE.xaiKey}`, encoding: "base64", mime: "image/png" },
  };
  const result = JSON.stringify(mapStrings(output, eventRedactor(new Vault(), "test", {}), isBinaryField).value);
  for (const token of [FAKE.awsKeyId, FAKE.githubPat, FAKE.slackBotToken, FAKE.groqKey, FAKE.anthropicKey, FAKE.xaiKey])
    expect(result.includes(token), token.slice(0, 8)).toBe(false);
});

it("knows an attachment by its first bytes, whatever type it is filed under", () => {
  const b = (...bytes: Array<number | string>) => Buffer.concat(bytes.map((x) => (typeof x === "string" ? Buffer.from(x, "latin1") : Buffer.from([x]))));
  const real: Array<[string, Buffer, string?]> = [
    ["png", PNG],
    ["jpeg", b(0xff, 0xd8, 0xff, 0xe0, "JFIF")],
    ["jpeg filed as png", b(0xff, 0xd8, 0xff, 0xe1), "image/png"],
    ["gif", b("GIF89a")],
    ["webp", b("RIFF", 0, 0, 0, 0, "WEBP")],
    ["wav", b("RIFF", 0, 0, 0, 0, "WAVE")],
    ["pdf", b("%PDF-1.7\n")],
    ["pdf after a newline", b("\n%PDF-1.4\n")],
    ["pdf after a byte-order mark", b(0xef, 0xbb, 0xbf, "%PDF-1.4\n")],
    ["heic", b(0, 0, 0, 0x18, "ftypheic")],
    ["mp3", b("ID3", 4, 0)],
    ["ogg", b("OggS")],
    ["bmp, filed as one", b("BM", 0x36, 0), "image/bmp"],
  ];
  for (const [name, head, type] of real) expect(isAttachmentPayload(payload(head, 600), type), name).toBe(true);
  const text = [
    FAKE.awsKeyId,
    FAKE.genericSecret,
    `AWS ${FAKE.awsKeyId}`,
    Buffer.from("just some text that is long enough").toString("base64"),
    Buffer.from("garbage %PDF-1.4").toString("base64"), // not at the start
    payload(Buffer.from("BM6\0"), 600), // two letters prove nothing unless the type says bitmap
    "",
  ];
  for (const value of text) expect(isAttachmentPayload(value, "image/png"), value.slice(0, 12)).toBe(false);
  expect(isAttachmentPayload(`${payload(PNG, 60)} ${FAKE.awsKeyId}`, "image/png")).toBe(false);
});
