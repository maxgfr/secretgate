import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { candidateRecords, GENERIC_KEYWORD, genericKeywordCost } from "../../src/verifier/generator.js";
import { GENERIC_KEYWORD_COST_LIMIT } from "../../src/verifier/verifier.js";
import { CORPUS } from "../fixtures/sg-cand-corpus.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const sha256 = (b: Buffer | string): string => createHash("sha256").update(b).digest("hex");
const gitBlob = (b: Buffer): string =>
  createHash("sha1")
    .update(Buffer.concat([Buffer.from(`blob ${b.length}\0`), b]))
    .digest("hex");

// The engine of the generator is the engine of commit 4e93cfa, byte for byte.
const FROZEN: Record<string, { blob: string; sha256: string }> = {
  "allowlist.ts": { blob: "583135a1102c8fad70884e41d1402c959b1d6cea", sha256: "d6358bd96f04d20bab13f667823305c7a7a9543394fd501f4f9a97a17f0121f4" },
  "entropy.ts": { blob: "5b02309fa59fd61635507043848ac41f8703f5a6", sha256: "9c3b51742d6d290b458997e60ff5c790722ce1be4a322c01a3ac687129030eba" },
  "luhn.ts": { blob: "a6a7d4aee86b4bf87dc838cbf7204fcd3b4c6e06", sha256: "f9ae7dccdd177a01fd3d5041207a1441e182dffa192101d2f9bfe4ccbcbb7f54" },
  "pragma.ts": { blob: "350c90f1239d90521fb70d9b59a96b58d95c4e3c", sha256: "d948ac9a925080fa356196f3e85ff6b00a33d1b9885fc4b38edd4ab7fba20cb7" },
  "rules.gen.ts": { blob: "a8cc8c106ec6d6e2587cb1e6c72c660994d9ecc5", sha256: "b92a83d5819c3f99fd81bc961b1da5c31482c70e414f473783eb01a4c0908c5c" },
  "scanner.ts": { blob: "e7b8f99da99cf64fb91ead34350b1da52034ca09", sha256: "1551d424fcb499eeeb29523f432913264d34edd21fcf5709e4b5779b5ec1a31d" },
};

// The export of the frozen generator (scripts/rule-candidates.mjs at 4e93cfa,
// `candidateRecords(text, engine, { sourcePath, raw: true, maxLine: 1000 })`)
// over the texts below, one JSON line per record and one "\n" after each text:
// 82 records, computed with that script on these texts.
const FROZEN_EXPORT_SHA256 = "5bfd222f09e5c8d9fbacf98191d420d865e8c191880dc24af74f72716c344f44";

function pinnedTexts(): Array<[string | null, string]> {
  const dir = join(root, "tests", "fixtures", "fp-corpus");
  const fp = readdirSync(dir)
    .sort()
    .map((f): [string, string] => [`tests/fixtures/fp-corpus/${f}`, readFileSync(join(dir, f), "utf8")]);
  return [...(CORPUS as Array<[string | null, string]>), ...fp, ...fp.map(([, t]): [null, string] => [null, t])];
}

describe("the frozen engine of sg-cand-1", () => {
  it("is the engine of commit 4e93cfa, byte for byte", () => {
    const dir = join(root, "src", "verifier", "sg-cand-1");
    expect(
      readdirSync(dir)
        .filter((f) => f.endsWith(".ts"))
        .sort(),
    ).toEqual(Object.keys(FROZEN).sort());
    for (const [file, pin] of Object.entries(FROZEN)) {
      const bytes = readFileSync(join(dir, file));
      expect(gitBlob(bytes), file).toBe(pin.blob);
      expect(sha256(bytes), file).toBe(pin.sha256);
    }
  });

  it("matches the commit itself, when this clone has it", () => {
    let has = true;
    try {
      execFileSync("git", ["cat-file", "-e", "4e93cfa2ee6e216caca9bc8e6f74cb565a991350^{commit}"], { cwd: root, stdio: "ignore" });
    } catch {
      has = false;
    }
    if (!has) return;
    for (const file of Object.keys(FROZEN)) {
      const original = execFileSync("git", ["show", `4e93cfa2ee6e216caca9bc8e6f74cb565a991350:src/engine/${file}`], { cwd: root });
      expect(readFileSync(join(root, "src", "verifier", "sg-cand-1", file)).equals(original), file).toBe(true);
    }
  });

  it("was generated from the rule set the default engine ships today (rules/gitleaks.toml)", () => {
    // Not a requirement of the verifier: when the default rules move, this
    // test says so, and the frozen copy stays as it is.
    expect(sha256(readFileSync(join(root, "rules", "gitleaks.toml")))).toBe("e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf");
  });
});

describe("candidateRecords", () => {
  it("writes the frozen generator's export, record for record", () => {
    const hash = createHash("sha256");
    let n = 0;
    for (const [path, text] of pinnedTexts()) {
      const records = candidateRecords(text, { ...(path ? { sourcePath: path } : {}), maxLine: 1000 });
      n += records.length;
      hash.update(`${records.map((r) => JSON.stringify(r)).join("\n")}\n`);
    }
    expect(n).toBe(82);
    expect(hash.digest("hex")).toBe(FROZEN_EXPORT_SHA256);
  });

  it("records the filters it turned off instead of applying them", () => {
    const all = pinnedTexts().flatMap(([path, text]) => candidateRecords(text, path ? { sourcePath: path } : {}));
    for (const flag of ["entropy", "placeholder", "allowlist", "stopword", "context", "pragma"] as const)
      expect(
        all.some((r) => r.filters[flag]),
        flag,
      ).toBe(true);
    expect(new Set(all.map((r) => r.rule))).toEqual(
      new Set([
        "generic-keyword",
        "password-assignment",
        "generic-api-key",
        "curl-auth-header",
        "aws-access-token",
        "credit-card-number",
        "url-credentials",
        "github-pat",
        "jwt",
        "private-key",
        "auth-scheme",
      ]),
    );
  });

  it("leaves `reported` out when asked, and nothing else changes", () => {
    for (const [path, text] of pinnedTexts()) {
      const opts = path ? { sourcePath: path } : {};
      const withIt = candidateRecords(text, opts).map(({ reported: _, ...r }) => r);
      expect(candidateRecords(text, { ...opts, reported: false })).toEqual(withIt);
    }
  });

  it("gives a file under the global path allowlist no candidate, and a text with no path its candidates", () => {
    const [, lock] = CORPUS.find(([p]) => p === "package-lock.json") as [string, string];
    expect(candidateRecords(lock, { sourcePath: "package-lock.json" })).toEqual([]);
    expect(candidateRecords(lock).length).toBeGreaterThan(0);
  });

  it("applies the user's disabled rules and allowlisted values as the frozen engine does", () => {
    const [, text] = CORPUS[0] as [string, string];
    const all = candidateRecords(text, { reported: false });
    const value = all.find((r) => r.rule === "generic-keyword")!.value;
    const without = candidateRecords(text, { reported: false, allowlist: { rules: ["generic-keyword"] } });
    expect(without.some((r) => r.rule === "generic-keyword")).toBe(false);
    // What another rule also proposes is still proposed, by that rule.
    expect(without.length).toBeGreaterThan(0);
    const valueAllowed = candidateRecords(text, { reported: false, allowlist: { sha256: [sha256(value)] } });
    expect(valueAllowed.some((r) => r.value === value)).toBe(false);
    expect(candidateRecords(text, { reported: false, allowlist: {} })).toEqual(all);
  });
});

describe("genericKeywordCost", () => {
  it("stays under the verifier's limit on ordinary text, and goes over it where the regex goes quadratic", () => {
    const line = ["const apiKey = process.env.API_KEY;", "const url = base + '/v1/items?page=' + page;", 'return render(items, { password: "x" });'].join("\n");
    const ordinary = `${line}\n`.repeat(4000);
    expect(ordinary.length).toBeGreaterThan(400_000);
    expect(genericKeywordCost(ordinary)).toBeLessThan(GENERIC_KEYWORD_COST_LIMIT);
    expect(genericKeywordCost("key".repeat(20_000))).toBeGreaterThan(GENERIC_KEYWORD_COST_LIMIT);
    expect(genericKeywordCost("key=".repeat(250_000))).toBeGreaterThan(GENERIC_KEYWORD_COST_LIMIT);
  });

  it("bounds what the regex really costs (40 KB of `key`: the bound is over the verifier's limit)", () => {
    const run = "key".repeat(13_334);
    const re = new RegExp(GENERIC_KEYWORD.re.source, "idg");
    const t0 = performance.now();
    expect([...run.matchAll(re)]).toEqual([]);
    const ms = performance.now() - t0;
    expect(genericKeywordCost(run)).toBeGreaterThan(GENERIC_KEYWORD_COST_LIMIT);
    expect(ms).toBeGreaterThan(1);
  });
});
