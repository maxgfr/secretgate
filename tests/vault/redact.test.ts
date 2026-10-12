import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { redactText, restorePlaceholders } from "../../src/redact.js";
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
