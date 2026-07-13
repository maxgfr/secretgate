import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { redactText, restorePlaceholders } from "../../src/redact.js";
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
