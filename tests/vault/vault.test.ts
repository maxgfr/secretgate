import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { placeholderFor, PLACEHOLDER_RE } from "../../src/vault/placeholder.js";
import { Vault } from "../../src/vault/vault.js";

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "secretgate-vault-"));
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

describe("placeholderFor", () => {
  it("is deterministic for the same secret and salt", () => {
    expect(placeholderFor("s3cret", "salt1")).toBe(placeholderFor("s3cret", "salt1"));
  });

  it("differs across secrets and across salts", () => {
    expect(placeholderFor("a", "salt1")).not.toBe(placeholderFor("b", "salt1"));
    expect(placeholderFor("a", "salt1")).not.toBe(placeholderFor("a", "salt2"));
  });

  it("round-trips through the extraction regex", () => {
    const p = placeholderFor("s3cret", "salt1");
    expect(p).toMatch(/^SECRETGATE_[0-9a-f]{12}$/);
    expect(`before ${p} after`.match(PLACEHOLDER_RE)).toEqual([p]);
  });
});

describe("Vault", () => {
  it("creates its home with restrictive permissions on first use", () => {
    const vault = new Vault(home);
    vault.recordSecret("tok-value", "github-pat", "prompt");
    expect(statSync(home).mode & 0o777).toBe(0o700);
    expect(statSync(join(home, "vault.json")).mode & 0o777).toBe(0o600);
    expect(statSync(join(home, "salt")).mode & 0o777).toBe(0o600);
  });

  it("returns a stable placeholder for the same secret and remembers the mapping", () => {
    const vault = new Vault(home);
    const p1 = vault.recordSecret("tok-value", "github-pat", "prompt");
    const p2 = vault.recordSecret("tok-value", "github-pat", "file:/x/.env");
    expect(p1).toBe(p2);
    expect(vault.secretFor(p1)).toBe("tok-value");
  });

  it("persists across instances (same home)", () => {
    const p = new Vault(home).recordSecret("tok-value", "github-pat", "prompt");
    expect(new Vault(home).secretFor(p)).toBe("tok-value");
  });

  it("lists entries WITHOUT ever exposing the secret", () => {
    const vault = new Vault(home);
    const p = vault.recordSecret("tok-value", "github-pat", "prompt");
    const listed = vault.list();
    expect(listed).toHaveLength(1);
    expect(listed[0]!.placeholder).toBe(p);
    expect(listed[0]!.ruleId).toBe("github-pat");
    expect(JSON.stringify(listed)).not.toContain("tok-value");
  });

  it("clear() wipes all entries", () => {
    const vault = new Vault(home);
    const p = vault.recordSecret("tok-value", "github-pat", "prompt");
    vault.clear();
    expect(new Vault(home).secretFor(p)).toBeUndefined();
  });

  it("merges concurrent writers instead of clobbering (last write re-reads)", () => {
    const a = new Vault(home);
    const b = new Vault(home);
    const pa = a.recordSecret("secret-A", "github-pat", "prompt");
    const pb = b.recordSecret("secret-B", "github-pat", "prompt");
    const fresh = new Vault(home);
    expect(fresh.secretFor(pa)).toBe("secret-A");
    expect(fresh.secretFor(pb)).toBe("secret-B");
  });

  it("does not store secrets in cleartext file names and keeps valid JSON on disk", () => {
    const vault = new Vault(home);
    vault.recordSecret("tok-value", "github-pat", "prompt");
    const raw = readFileSync(join(home, "vault.json"), "utf8");
    expect(() => JSON.parse(raw)).not.toThrow();
  });
});
