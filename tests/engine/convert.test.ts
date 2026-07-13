import { describe, expect, it } from "vitest";
// The converter is a dev-time script (it GENERATES src/engine/rules.gen.ts),
// so it lives outside src/ and is imported here as plain ESM.
import { convertConfig, convertGoRegex } from "../../scripts/convert-rules.mjs";

describe("convertGoRegex — Go/RE2 to JS", () => {
  it("hoists a leading (?i) to the i flag", () => {
    const r = convertGoRegex("(?i)abc[0-9]{4}");
    expect(r.source).toBe("abc[0-9]{4}");
    expect(r.flags).toContain("i");
    expect(r.loosened).toEqual([]);
  });

  it("hoists a mid-pattern (?i) to the i flag and reports loosening", () => {
    const r = convertGoRegex("\\b(p8e-(?i)[a-z0-9]{32})\\b");
    expect(r.flags).toContain("i");
    expect(r.source).toBe("\\b(p8e-[a-z0-9]{32})\\b");
    expect(r.loosened.length).toBeGreaterThan(0);
  });

  it("converts (?i:...) groups by hoisting i", () => {
    const r = convertGoRegex("foo(?i:bar|baz)qux");
    expect(r.source).toBe("foo(?:bar|baz)qux");
    expect(r.flags).toContain("i");
    expect(r.loosened.length).toBeGreaterThan(0);
  });

  it("converts (?-i:...) groups to plain groups (loosened)", () => {
    const r = convertGoRegex("(?i)x(?-i:[Aa]pi|API)y");
    expect(r.source).toBe("x(?:[Aa]pi|API)y");
    expect(r.flags).toContain("i");
    expect(r.loosened.length).toBeGreaterThan(0);
  });

  it("rewrites dots inside (?s:...) groups to [\\s\\S] — exact, not loosened", () => {
    const r = convertGoRegex("a(?s:b.c)d");
    expect(r.source).toBe("a(?:b[\\s\\S]c)d");
    expect(r.loosened).toEqual([]);
    // a dot inside a character class must NOT be rewritten
    const r2 = convertGoRegex("(?s:[.x].)");
    expect(r2.source).toBe("(?:[.x][\\s\\S])");
  });

  it("converts (?P<name> to (?<name>", () => {
    const r = convertGoRegex("(?P<key>[a-z]+)");
    expect(r.source).toBe("(?<key>[a-z]+)");
  });

  it("handles nested groups inside flag groups", () => {
    const r = convertGoRegex("(?s:a(?:b.c)+d)");
    expect(r.source).toBe("(?:a(?:b[\\s\\S]c)+d)");
  });

  it("produces a compilable regex for every construct", () => {
    for (const src of ["(?i)abc", "a(?s:.)b", "(?i)x(?-i:Y)z", "(?P<n>a)"]) {
      const r = convertGoRegex(src);
      expect(() => new RegExp(r.source, r.flags + "dg")).not.toThrow();
      expect(r.source).not.toMatch(/\(\?[a-zA-Z-]*[is][a-zA-Z-]*[):]/);
    }
  });
});

describe("convertConfig — full vendored gitleaks.toml", () => {
  it("emits every upstream rule, all compilable, none silently dropped", async () => {
    const { rules, dropped } = await convertConfig();
    expect(rules.length).toBeGreaterThanOrEqual(200);
    expect(dropped).toEqual([]);
    for (const rule of rules) {
      expect(() => new RegExp(rule.regex.source, rule.regex.flags + "dg"), rule.id).not.toThrow();
      expect(rule.regex.source, rule.id).not.toMatch(/\(\?[a-zA-Z-]*[is][a-zA-Z-]*[):]/);
    }
  });

  it("keeps entropy thresholds, keywords and stopword allowlists", async () => {
    const { rules } = await convertConfig();
    const generic = rules.find((r) => r.id === "generic-api-key");
    expect(generic).toBeDefined();
    expect(generic!.entropy).toBeCloseTo(3.5, 5);
    expect(generic!.keywords).toContain("key");
    const stopwords = (generic!.allowlists ?? []).flatMap((a) => a.stopwords ?? []);
    expect(stopwords.length).toBeGreaterThan(50);
  });

  it("spot-check: aws-access-key-id matches a constructed AKIA token", async () => {
    const { rules } = await convertConfig();
    const aws = rules.find((r) => r.id === "aws-access-token" || r.id === "aws-access-key-id");
    expect(aws).toBeDefined();
    const token = "AKIA" + "IOSFODNN7EXAMPLE";
    expect(new RegExp(aws!.regex.source, aws!.regex.flags).test(`key = ${token}`)).toBe(true);
  });

  it("spot-check: github-pat matches a constructed ghp_ token", async () => {
    const { rules } = await convertConfig();
    const pat = rules.find((r) => r.id === "github-pat");
    expect(pat).toBeDefined();
    const token = "ghp_" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0dF6hJ9";
    expect(new RegExp(pat!.regex.source, pat!.regex.flags).test(token)).toBe(true);
  });

  it("carries the global allowlist (paths + stopwords/regexes if present)", async () => {
    const { globalAllowlist } = await convertConfig();
    expect(globalAllowlist.paths.length).toBeGreaterThan(10);
    for (const p of globalAllowlist.paths) {
      expect(() => new RegExp(p)).not.toThrow();
    }
  });
});
