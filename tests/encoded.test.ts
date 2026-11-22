import { expect, it } from "vitest";
import { scan } from "../src/engine/scanner.js";
const token = "ghp_Ab3dE6gH9jK2mN5pQ8rS1tU4vW7xY0zC3fG6";
for (const [encoding, value] of [
  ["base64", Buffer.from(token).toString("base64")],
  ["hex", Buffer.from(token).toString("hex")],
  ["percent", [...token].map((x) => "%" + x.charCodeAt(0).toString(16)).join("")],
]) {
  it(`detects original ${encoding} span`, () => {
    const text = "value=" + value;
    const f = scan(text);
    expect(f.some((x) => x.secret === value && x.start === 6 && x.end === text.length)).toBe(true);
  });
}
it("keeps ordinary encoded text", () => expect(scan("value=" + Buffer.from("ordinary build output").toString("base64"))).toEqual([]));
it("preserves assignment context", () => expect(scan('password="' + Buffer.from("rV9!62a8ef31d057b4c9").toString("base64") + '"').length).toBeGreaterThan(0));
it("does not reconstruct split tokens", () => expect(scan("part1=" + token.slice(0, 20) + "\npart2=" + token.slice(20))).toEqual([]));

it("handles uppercase hex", () => expect(scan(Buffer.from(token).toString("hex").toUpperCase()).length).toBeGreaterThan(0));
it("handles unpadded Base64", () => expect(scan(Buffer.from(token).toString("base64").replace(/=+$/, "")).length).toBeGreaterThan(0));
it("handles mixed percent encoding", () => expect(scan(token.replace("_", "%5f")).length).toBeGreaterThan(0));
it("does not decode twice", () => expect(scan(Buffer.from(Buffer.from(token).toString("base64")).toString("base64"))).toEqual([]));
it("ignores binary bytes", () => expect(scan(Buffer.from([0xff, 0xfe, 0, 0xff, 0xfe, 0, 0xff]).toString("base64"))).toEqual([]));
it("retains both occurrences", () => {
  const v = Buffer.from(token).toString("hex");
  expect(scan(v + "\n" + v).filter((f) => f.encoding === "hex")).toHaveLength(2);
});
it("preserves Unicode offsets", () => {
  const v = Buffer.from(token).toString("base64");
  expect(scan("é 🔑 " + v).find((f) => f.encoding)?.start).toBe(5);
});
it("honors disabled detector rules", () => {
  const v = Buffer.from(token).toString("base64");
  expect(scan(v, { allowlist: { rules: ["github-pat"] } })).toEqual([]);
});
it("honors original value exceptions", async () => {
  const { sha256 } = await import("../src/engine/allowlist.js");
  const v = Buffer.from(token).toString("base64");
  expect(scan(v, { allowlist: { sha256: [sha256(v)] } })).toEqual([]);
});
it("honors decoded value exceptions", async () => {
  const { sha256 } = await import("../src/engine/allowlist.js");
  expect(scan(Buffer.from(token).toString("base64"), { allowlist: { sha256: [sha256(token)] } })).toEqual([]);
});
it("restores original encoding through the vault", async () => {
  const { mkdtempSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { Vault } = await import("../src/vault/vault.js");
  const { redactText, restorePlaceholders } = await import("../src/redact.js");
  const dir = mkdtempSync(join(tmpdir(), "encoding-vault-"));
  const old = process.env.SECRETGATE_HOME;
  process.env.SECRETGATE_HOME = dir;
  try {
    const vault = new Vault();
    const value = "value=" + Buffer.from(token).toString("base64");
    const redacted = redactText(value, vault, "test");
    expect(redacted.text).not.toContain(Buffer.from(token).toString("base64"));
    expect(restorePlaceholders(redacted.text, vault).text).toBe(value);
  } finally {
    if (old === undefined) delete process.env.SECRETGATE_HOME;
    else process.env.SECRETGATE_HOME = old;
    rmSync(dir, { recursive: true, force: true });
  }
});
