import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { scan } from "../../src/engine/scanner.js";
import { RedactionUnsettledError, redactText, restorePlaceholders } from "../../src/redact.js";
import { placeholderFor } from "../../src/vault/placeholder.js";
import { Vault } from "../../src/vault/vault.js";
import { FAKE } from "../fixtures/fake-tokens.js";

let home: string;
let vault: Vault;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "secretgate-redact-"));
  vault = new Vault(home);
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

describe("redactText", () => {
  it("replaces each secret with a stable placeholder and keeps the rest intact", () => {
    const text = `before\nkey: ${FAKE.awsKeyId}\nafter`;
    const r = redactText(text, vault, "test");
    expect(r.text).not.toContain(FAKE.awsKeyId);
    expect(r.text).toMatch(/key: SECRETGATE_[0-9a-f]{12,16}/);
    expect(r.text.startsWith("before\n")).toBe(true);
    expect(r.text.endsWith("\nafter")).toBe(true);
    expect(r.findings).toHaveLength(1);
  });

  it("uses the SAME placeholder for the same secret appearing twice", () => {
    const r = redactText(`a=${FAKE.githubPat}\nb=${FAKE.githubPat}`, vault, "test");
    const found = r.text.match(/SECRETGATE_[0-9a-f]{12,16}/g)!;
    expect(found).toHaveLength(2);
    expect(found[0]).toBe(found[1]);
  });

  it("handles multiple distinct secrets with offset-safe replacement", () => {
    const text = `x=${FAKE.awsKeyId} then y=${FAKE.githubPat} end`;
    const r = redactText(text, vault, "test");
    expect(r.text).not.toContain(FAKE.awsKeyId);
    expect(r.text).not.toContain(FAKE.githubPat);
    expect(r.text.endsWith(" end")).toBe(true);
    expect(new Set(r.text.match(/SECRETGATE_[0-9a-f]{12,16}/g)).size).toBe(2);
  });

  it("leaves no part of a flagged value behind when a vendor token sits inside it", () => {
    const rest = "wJalrXUtnFEMI" + "K7MDENGbPxRfiCY" + "zQ9kT4mB2x";
    const r = redactText(`api_key = "${FAKE.awsKeyId}:${rest}"`, vault, "test");
    expect(r.text).not.toContain(rest);
    expect(r.text).not.toContain(FAKE.awsKeyId);
    expect(restorePlaceholders(r.text, vault).text).toBe(`api_key = "${FAKE.awsKeyId}:${rest}"`);
  });

  // A wider rule often captures a stray character around a token (the dot that
  // ends a sentence). Once the token is a placeholder, that rule saw
  // `SECRETGATE_….` as a new secret: the redacted text was flagged again.
  it("is stable: redacted text holds nothing to redact", () => {
    for (const text of [
      `token: ${FAKE.githubPat}.`,
      `TOKEN=${FAKE.githubPat}.\n`,
      `api_key = "x-${FAKE.githubPat}"`,
      `password = "ab:${FAKE.awsKeyId}"`,
      `secret = "${FAKE.awsKeyId}!"`,
      `key=${FAKE.awsKeyId}=`,
      `auth_token = '${FAKE.slackBotToken}.x'`,
      `secret_key = ${FAKE.groqKey}__`,
    ]) {
      const once = redactText(text, vault, "test");
      expect(once.findings.length, text).toBeGreaterThan(0);
      const twice = redactText(once.text, vault, "test");
      expect(twice.findings, once.text).toEqual([]);
      expect(restorePlaceholders(once.text, vault).text).toBe(text);
    }
  });

  // What the model receives is scanned again by the hook that runs before the
  // next request. Whatever redactText returns must hold nothing it would flag.
  it("returns a fixed point: its own output holds no finding", () => {
    const random = FAKE.genericSecret;
    for (const text of [
      `${FAKE.githubPat}: ${random}`,
      `${FAKE.githubPat}=${random}`,
      `${FAKE.awsKeyId},${random}`,
      `id,key\n1,${FAKE.githubPat} ${random}`,
      `pushed with ${FAKE.githubPat}: build-2026.11.14-r7xQ`,
      `${FAKE.awsKeyId},${random},${random.split("").reverse().join("")}`,
      `auth_token = "${FAKE.githubPat}:1234"`,
      `{"a":"${FAKE.githubPat}","b":"${random}"}`,
      `url: https://svc:${random}@host/x, token: ${FAKE.githubPat}.`,
    ]) {
      const once = redactText(text, vault, "test");
      expect(redactText(once.text, vault, "test").findings, once.text).toEqual([]);
      expect(restorePlaceholders(once.text, vault).text, text).toBe(text);
    }
  });

  // The name in front of a value is read to decide about it. Once the token
  // before that name is a placeholder, the placeholder's text ("SECRET…") must
  // not read as part of the name: here it used to cancel an exemption one
  // value per round, and the rounds ran out with values left.
  it("settles when names and values follow a token, however many", () => {
    const value = (i: number) => `Zx9kLm2Qw8rT5yUq${i}Pk3Rt7`;
    for (const name of ["cache_key", "public_key", "pubkey", "fingerprint", "api_key"]) {
      const text = `auth=${FAKE.githubPat} ${[1, 2, 3, 4, 5, 6].map((i) => `${name}=${value(i)}`).join(" ")}`;
      const once = redactText(text, vault, "test");
      expect(redactText(once.text, vault, "test").findings, once.text).toEqual([]);
      // The verdict on each value is the one it gets with no token in front.
      const alone = redactText(`${name}=${value(1)}`, vault, "test").findings.length > 0;
      expect(once.text.includes(value(6)), name).toBe(!alone);
    }
    // The spelling upstream's own allowlist does not cover: the exemption is
    // secretgate's, and it read the placeholder as a word of the name.
    const spaced = `${FAKE.githubPat} public key: ${value(1)}\n${FAKE.githubPat} Public key: ${value(2)}`;
    const once = redactText(spaced, vault, "test");
    expect(redactText(once.text, vault, "test").findings, once.text).toEqual([]);
    expect(once.text).toContain(value(2));
  });

  // Tokens, names, separators and placeholders (real, forged, long) in random
  // order: whatever redactText returns holds nothing a second scan flags, and
  // restores to what the input restores to.
  it("returns a fixed point over generated mixes", () => {
    const awsSecret = "wJalrXUtnFEMI" + "/K7MDENG/" + "bPxRfiCYzQ9kT4mB2x";
    const tokens = [FAKE.githubPat, FAKE.awsKeyId, FAKE.slackBotToken, FAKE.genericSecret, awsSecret, FAKE.groqKey, "Zx9kLm2Qw8rT5yU", FAKE.visaPan];
    const names = [
      "password",
      "pwd",
      "api_key",
      "token",
      "secret",
      "auth",
      "cache_key",
      "public_key",
      "public key",
      "pubkey",
      "fingerprint",
      "stripe_publishable_key",
      "id",
      "AWS",
    ];
    const separators = [":", "=", ",", " ", " ", '"', "'", "\n", "\r\n", ".", "-", "_", "/", "@", "://", "!", ": ", " = ", "; "];
    const placeholders = [vault.recordSecret("Pq7Lm2Zx9kRt5Wv8", "test", "mix"), "SECRETGATE_" + "0123456789ab", "SECRETGATE_" + "0123456789abcdef"];
    const words = ["postgres", "admin", "é", "x", "cafe", "12", "abc", "pk_live_", "Bearer", "3f786850e387550fdab836ed7e6dc881de23001b"];
    const parts = [...tokens, ...tokens, ...names, ...names, ...separators, ...separators, ...placeholders, ...words];
    let seed = 20261114;
    const next = (n: number) => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed % n;
    };
    for (let i = 0; i < 4000; i++) {
      let text = "";
      for (let k = 2 + next(9); k > 0; k--) text += parts[next(parts.length)];
      const once = redactText(text, vault, "mix");
      const again = scan(once.text, { pragmas: false });
      expect(
        again.map((f) => `${f.ruleId}:${f.secret}`),
        JSON.stringify(text),
      ).toEqual([]);
      expect(restorePlaceholders(once.text, vault).text, JSON.stringify(text)).toBe(restorePlaceholders(text, vault).text);
    }
  });

  // If the rounds ever run out with something left, the text is not clean and
  // must not be returned as if it were: the caller fails closed.
  it("throws rather than return text it could not settle", () => {
    let n = 0;
    const neverClean = {
      recordSecrets: (items: unknown[]) => items.map(() => `ghp_${"aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0dF6h".slice(0, 34)}${String(n++).padStart(2, "0")}`),
    } as unknown as Vault;
    expect(() => redactText(`token: ${FAKE.githubPat}`, neverClean, "test")).toThrow(RedactionUnsettledError);
  });

  it("still redacts what is added around a placeholder", () => {
    const first = redactText(`key: ${FAKE.awsKeyId}`, vault, "test").text.slice("key: ".length);
    const composed = `password = "${first}:Zx9kLm2Qw8rT5yU"`;
    const r = redactText(composed, vault, "test");
    expect(r.text).not.toContain("Zx9kLm2Qw8rT5yU");
    // The placeholder of a value that held a placeholder leads back to the real thing.
    expect(restorePlaceholders(r.text, vault).text).toBe(`password = "${FAKE.awsKeyId}:Zx9kLm2Qw8rT5yU"`);
  });

  it("returns the text unchanged when nothing is found", () => {
    const r = redactText("nothing to see here", vault, "test");
    expect(r.text).toBe("nothing to see here");
    expect(r.findings).toEqual([]);
  });
});

describe("restorePlaceholders", () => {
  it("substitutes known placeholders back to the real value", () => {
    const r = redactText(`key=${FAKE.awsKeyId}`, vault, "test");
    const placeholder = r.text.match(/SECRETGATE_[0-9a-f]{12,16}/)![0];
    const restored = restorePlaceholders(`export AWS_KEY=${placeholder} # from agent`, vault);
    expect(restored.text).toBe(`export AWS_KEY=${FAKE.awsKeyId} # from agent`);
    expect(restored.restored).toBe(1);
  });

  it("leaves unknown placeholders untouched", () => {
    const restored = restorePlaceholders("value=SECRETGATE_deadbeef1234", vault);
    expect(restored.text).toBe("value=SECRETGATE_deadbeef1234");
    expect(restored.restored).toBe(0);
  });

  it("is idempotent: redacting already-redacted text finds nothing (placeholders are not secrets)", () => {
    const once = redactText(`CI_TOKEN=${FAKE.githubPat}`, vault, "test");
    expect(once.replaced).toHaveLength(1);
    // the redacted text (containing a placeholder in assignment context) must
    // NOT be flagged again — otherwise a resent redacted prompt would re-block
    const twice = redactText(once.text, vault, "test");
    expect(twice.findings).toEqual([]);
    expect(twice.text).toBe(once.text);
  });
});

describe("redaction at volume", () => {
  const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const token = (i: number): string => {
    let s = "";
    let x = i * 7919 + 97;
    for (let k = 0; k < 36; k++) {
      x = (x * 1103515245 + 12345) & 0x7fffffff;
      s += ALNUM[x % ALNUM.length];
    }
    return `ghp${"_"}${s}`;
  };

  it("redacts 3000 distinct secrets in one text in under a second", () => {
    const secrets = Array.from({ length: 3000 }, (_, i) => token(i));
    const text = secrets.map((s, i) => `T${i}=${s}`).join("\n");
    const started = performance.now();
    const r = redactText(text, vault, "bulk");
    expect(performance.now() - started).toBeLessThan(1000);
    expect(r.replaced).toHaveLength(3000);
    for (const s of secrets.slice(0, 50)) expect(r.text).not.toContain(s);
    expect(restorePlaceholders(r.text, vault).text).toBe(text);
  });

  it("gives each secret the same placeholder as one-at-a-time recording", () => {
    const otherHome = mkdtempSync(join(tmpdir(), "secretgate-redact-b-"));
    try {
      const secrets = [FAKE.githubPat, FAKE.awsKeyId];
      const bulk = redactText(secrets.join("\n"), vault, "bulk").replaced.map((r) => r.placeholder);
      writeFileSync(join(otherHome, "salt"), readFileSync(join(home, "salt"), "utf8"));
      const other = new Vault(otherHome);
      expect(secrets.map((s) => other.recordSecret(s, "x", "one"))).toEqual(bulk);
    } finally {
      rmSync(otherHome, { recursive: true, force: true });
    }
  });
});

describe("restorePlaceholders next to hex characters", () => {
  it.each(["cafe", "0", "beef42", "0123456789abcdef"])("restores a placeholder followed by %j", (suffix) => {
    const { text } = redactText(`k: ${FAKE.githubPat}`, vault, "test");
    const placeholder = /SECRETGATE_[0-9a-f]+/.exec(text)![0];
    expect(restorePlaceholders(`${placeholder}${suffix}`, vault).text).toBe(`${FAKE.githubPat}${suffix}`);
  });

  it("restores a 16-hex placeholder (collision form) even when followed by hex", () => {
    // Occupy the secret's 12-hex slot with another value so it is recorded under 16.
    vault.recordSecret("seed-value-1", "x", "t");
    const salt = readFileSync(join(home, "salt"), "utf8");
    const short = placeholderFor(FAKE.githubPat, salt, 12);
    const file = JSON.parse(readFileSync(join(home, "vault.json"), "utf8"));
    file.entries[short] = { secret: "occupant", ruleId: "x", firstSeen: "", sources: [] };
    writeFileSync(join(home, "vault.json"), JSON.stringify(file));
    const long = vault.recordSecret(FAKE.githubPat, "x", "t");
    expect(long).toBe(placeholderFor(FAKE.githubPat, salt, 16));
    expect(restorePlaceholders(`${long}ff`, vault).text).toBe(`${FAKE.githubPat}ff`);
    expect(restorePlaceholders(`${short}ff`, vault).text).toBe("occupantff");
  });

  it("leaves unknown placeholders untouched", () => {
    expect(restorePlaceholders("SECRETGATE_0123456789abcdef00", vault).text).toBe("SECRETGATE_0123456789abcdef00");
  });
});
