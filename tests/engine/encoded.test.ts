import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { sha256 } from "../../src/engine/allowlist.js";
import { scan } from "../../src/engine/scanner.js";
import { redactText, restorePlaceholders } from "../../src/redact.js";
import { Vault } from "../../src/vault/vault.js";
import { FAKE } from "../fixtures/fake-tokens.js";

// Built by concatenation and encoded at run time: the repository never holds
// a token-shaped literal, encoded or not (see tests/fixtures/fake-tokens.ts).
const token = "ghp_" + "Ab3dE6gH9jK2mN5pQ8rS1tU4vW7xY0zC3fG6";
const b64 = (s: string): string => Buffer.from(s).toString("base64");
const hex = (s: string): string => Buffer.from(s).toString("hex");
const pct = (s: string): string => [...Buffer.from(s)].map((b) => "%" + b.toString(16).padStart(2, "0")).join("");
const encoded = (text: string) => scan(text).filter((f) => f.encoding !== undefined);

describe("scan — encoded secrets", () => {
  for (const [encoding, value] of [
    ["base64", b64(token)],
    // A prefix whose base64url holds `_`, so it is not also plain base64.
    ["base64url", Buffer.from("key " + token + "?").toString("base64url")],
    ["hex", hex(token)],
    ["percent", pct(token)],
  ] as const) {
    it(`finds a ${encoding}-encoded token on its original span`, () => {
      const text = "value=" + value + "\n";
      const findings = scan(text);
      expect(findings).toHaveLength(1);
      const f = findings[0]!;
      expect(f).toMatchObject({ ruleId: "github-pat", encoding, secret: value, match: value, start: 6, end: 6 + value.length, line: 0 });
      expect(text.slice(f.start, f.end)).toBe(value);
    });
  }

  it("leaves ordinary encoded text alone", () => {
    expect(scan("value=" + b64("ordinary build output"))).toEqual([]);
    expect(scan("value=" + hex("ordinary build output"))).toEqual([]);
    expect(scan("see https://example.com/search?q=hello%20world%20again")).toEqual([]);
  });

  it("reads the decoded value in its line: the name it is assigned to still counts", () => {
    // `%` stops the generic rule on the text as written; decoded, the value
    // is an api_key assignment.
    const value = "Xk9mQ2vR7t%2EL4pW8zB3nH";
    const text = "api_key=" + value;
    const f = scan(text);
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ ruleId: "generic-api-key", encoding: "percent", secret: value, start: 8 });
    expect(scan("color=" + value)).toEqual([]);
  });

  it("flags a base64 password in a quoted assignment", () => {
    const value = b64("rV9!62a8ef31d057b4c9");
    const f = scan('password="' + value + '"');
    expect(f).toHaveLength(1);
    expect(f[0]!.secret).toBe(value);
  });

  it("keeps the plain finding when a rule already flags the encoded string as written", () => {
    // password-assignment takes the base64 value as it is; github-pat finds
    // the token inside. One finding remains, the plain one.
    const value = b64(token);
    const f = scan('password="' + value + '"');
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ ruleId: "password-assignment", secret: value });
    expect("encoding" in f[0]!).toBe(false);
  });

  it("does not reconstruct a token split over two lines", () => {
    expect(scan("part1=" + b64(token.slice(0, 20)) + "\npart2=" + b64(token.slice(20)))).toEqual([]);
  });

  it("decodes uppercase hex, unpadded base64 and a single escape", () => {
    expect(encoded(hex(token).toUpperCase())).toMatchObject([{ encoding: "hex" }]);
    const unpadded = b64(token).replace(/=+$/, "");
    expect(unpadded.length % 4).not.toBe(0);
    expect(encoded(unpadded)).toMatchObject([{ encoding: "base64", secret: unpadded }]);
    expect(encoded(token.replace("_", "%5F"))).toMatchObject([{ encoding: "percent", ruleId: "github-pat" }]);
    expect(encoded(token.replace("_", "%5f"))).toMatchObject([{ encoding: "percent", ruleId: "github-pat" }]);
  });

  it("decodes one layer only", () => {
    expect(scan(b64(b64(token)))).toEqual([]);
    expect(scan(b64(hex(token)))).toEqual([]);
  });

  it("ignores runs that decode to binary or to control characters", () => {
    expect(scan(Buffer.from([0xff, 0xfe, 0, 0xff, 0xfe, 0, 0xff, 0xfe, 0]).toString("base64"))).toEqual([]);
    expect(scan(b64("\u0001" + token))).toEqual([]);
  });

  it("rejects padding that does not complete a group of four", () => {
    const unpadded = b64(token).replace(/=+$/, "");
    expect(scan("x " + unpadded + "=")).toEqual([]);
  });

  it("reports every occurrence, each on its own line", () => {
    const v = hex(token);
    expect(encoded(v + "\n" + v).map((f) => [f.line, f.start])).toEqual([
      [0, 0],
      [1, v.length + 1],
    ]);
  });

  it("reports offsets in UTF-16 units, after non-ASCII text", () => {
    const v = b64(token);
    const text = "é 🔑 " + v;
    const f = encoded(text)[0]!;
    expect(f.start).toBe(5);
    expect(text.slice(f.start, f.end)).toBe(v);
  });

  it("honors a disabled rule", () => {
    expect(scan(b64(token), { allowlist: { rules: ["github-pat"] } })).toEqual([]);
  });

  it("honors the sha256 allowlist, of the encoded and of the decoded value", () => {
    const v = b64(token);
    expect(scan(v, { allowlist: { sha256: [sha256(v)] } })).toEqual([]);
    expect(scan(v, { allowlist: { sha256: [sha256(token)] } })).toEqual([]);
    expect(scan(v, { allowlist: { sha256: [sha256("something else")] } })).toHaveLength(1);
  });

  it("honors path scopes and path allowlists", () => {
    // freemius-secret-key only applies to PHP files. The `!` keeps the generic
    // rule out of it.
    const key = "sk_" + "Ab3dE6gH9jK2mN5p!Q8rS1tU4vW7x";
    const v = b64(`'secret_key' => '${key}'`);
    expect(scan(v, { sourcePath: "src/settings.php" })).toMatchObject([{ ruleId: "freemius-secret-key", encoding: "base64", secret: v }]);
    expect(scan(v, { sourcePath: "src/settings.js" })).toEqual([]);
    expect(scan(b64(token), { sourcePath: "tests/fixtures/a.txt", allowlist: { paths: ["tests/fixtures/**"] } })).toEqual([]);
    expect(scan(b64(token), { sourcePath: "node_modules/pkg/index.js" })).toEqual([]);
  });

  it("finds a token in a base64'd multi-line .env", () => {
    const v = b64("GITHUB_TOKEN=" + token + "\nOTHER=x\n");
    expect(scan("ENV_FILE=" + v)).toMatchObject([{ ruleId: "github-pat", encoding: "base64", secret: v, start: 9 }]);
  });

  it("finds a base64'd PEM private key", () => {
    const v = b64(FAKE.privateKey + "\n");
    const text = "data:\n  tls.key: " + v + "\n";
    expect(scan(text)).toMatchObject([{ ruleId: "private-key", encoding: "base64", secret: v, line: 1 }]);
  });

  it("honors allowlist pragmas on the original lines", () => {
    const v = b64(token);
    expect(scan("# pragma: allowlist nextline secret\nvalue: " + v)).toEqual([]);
    expect(scan("value: " + v + " # pragma: allowlist secret")).toEqual([]);
    expect(scan("value: " + v + " # gitleaks:allow")).toEqual([]);
    expect(scan("# pragma: allowlist nextline secret\nvalue: " + v, { pragmas: false })).toMatchObject([{ encoding: "base64", line: 1 }]);
    // A pragma inside the encoded text is not one.
    expect(scan(b64(token + " # pragma: allowlist secret"))).toHaveLength(1);
  });

  it("never decodes one of its own placeholders", () => {
    expect(scan("x SECRETGATE_0123456789ab y")).toEqual([]);
  });

  it("sets `encoding` only on findings made from a decoded value", () => {
    const f = scan(`a=${FAKE.githubPat}\nb=${b64(token)}`);
    expect(f.map((x) => [x.ruleId, x.encoding])).toEqual([
      ["github-pat", undefined],
      ["github-pat", "base64"],
    ]);
    expect("encoding" in f[0]!).toBe(false);
  });

  it("finds a plain secret once when the same line holds an encoded run", () => {
    const f = scan(`token ${FAKE.githubPat} next to ${b64("ordinary build output")}`);
    expect(f.map((x) => [x.ruleId, x.encoding])).toEqual([["github-pat", undefined]]);
  });

  it("redacts the encoded string whole and restores it as written", () => {
    const dir = mkdtempSync(join(tmpdir(), "secretgate-encoded-"));
    const old = process.env.SECRETGATE_HOME;
    process.env.SECRETGATE_HOME = dir;
    try {
      const vault = new Vault();
      for (const value of [b64(token), hex(token), pct(token)]) {
        const text = "value=" + value + "\nnext line";
        const redacted = redactText(text, vault, "test");
        expect(redacted.text).not.toContain(value);
        expect(redacted.text).toMatch(/^value=SECRETGATE_[0-9a-f]{12}\nnext line$/);
        expect(scan(redacted.text)).toEqual([]);
        expect(restorePlaceholders(redacted.text, vault).text).toBe(text);
      }
    } finally {
      if (old === undefined) delete process.env.SECRETGATE_HOME;
      else process.env.SECRETGATE_HOME = old;
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("scan — encoded runs at volume", () => {
  // The decoded pass has no count cap: one that throws failed `secretgate
  // scan` on a 10 KB file of links (and blocked hooks on ordinary bundles);
  // one that stops quietly lets decoys hide a real secret after them.
  it("scans 200 distinct lines of percent-encoded links, with and without a deadline", () => {
    const text = Array.from({ length: 200 }, (_, i) => `see https://example.com/search?q=hello%20world%20${i}`).join("\n");
    expect(scan(text)).toEqual([]);
    expect(scan(text, { deadlineMs: 5000 })).toEqual([]);
  });

  it("scans thousands of decodable, harmless base64 and hex runs", () => {
    const lines: string[] = [];
    for (let i = 0; i < 3000; i++) lines.push(`id: ${b64(`harmless value ${i}`)}`, `digest: ${hex(`harmless value ${i}`)}`);
    const text = lines.join("\n");
    expect(scan(text)).toEqual([]);
    expect(scan(text, { deadlineMs: 5000 })).toEqual([]);
  });

  it("still finds the real secret after thousands of decoys", () => {
    const decoys = Array.from({ length: 3000 }, (_, i) => b64(`decoy number ${i}`)).join("\n");
    const v = b64(token);
    expect(scan(decoys + "\n" + v, { deadlineMs: 5000 })).toMatchObject([{ ruleId: "github-pat", encoding: "base64", line: 3000 }]);
  });
});
