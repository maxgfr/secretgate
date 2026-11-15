import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { sha256 } from "../../src/engine/allowlist.js";
import { scan } from "../../src/engine/scanner.js";
import { redactText } from "../../src/redact.js";
import { Vault } from "../../src/vault/vault.js";
import { ASSETS, assetDir, assetStates, fetchAssets, readAsset } from "../../src/verifier/assets.js";
import { readVerifierConfig, type VerifierConfig } from "../../src/verifier/config.js";
import {
  type EngineLoader,
  loadEngine,
  repositoryPath,
  VERIFIER_RULE_ID,
  VerifierAssetError,
  type VerifierEngine,
  VerifierSession,
} from "../../src/verifier/verifier.js";
import { FAKE } from "../fixtures/fake-tokens.js";

// The verifier with a FAKE engine: no assets, no WebAssembly. The fake answers
// a probability per candidate from its value.
const ON: VerifierConfig = { enabled: true, threshold: "f1" };
const value = ["Qm7", "xR2", "pL9", "vN4", "kT8"].join("");
const other = ["Hb4", "wE9", "zN2", "cK7"].join("");

function fakeEngine(p: (c: Record<string, unknown>) => number, seen: Array<Record<string, unknown>> = []): EngineLoader {
  return () =>
    ({
      build: "simd128",
      tau: 0.5,
      judge: (c) => {
        seen.push(c);
        return p(c);
      },
      state: () => "",
    }) satisfies VerifierEngine;
}
const acceptAll = fakeEngine(() => 0.9);

let home: string;
beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "secretgate-verifier-"));
  process.env.SECRETGATE_HOME = home;
});
afterEach(() => {
  delete process.env.SECRETGATE_HOME;
  rmSync(home, { recursive: true, force: true });
});

describe("readVerifierConfig", () => {
  it("is off unless config.json says otherwise, and off when the entry is not understood", () => {
    expect(readVerifierConfig(undefined)).toEqual({ enabled: false, threshold: "f1" });
    expect(readVerifierConfig({ enabled: true })).toEqual({ enabled: true, threshold: "f1" });
    expect(readVerifierConfig({ enabled: true, threshold: "f05" })).toEqual({ enabled: true, threshold: "f05" });
    for (const bad of [true, "on", null, [], { enabled: "yes" }, { enabled: true, threshold: "f3" }, { enabled: true, tau: 0.1 }]) {
      const c = readVerifierConfig(bad);
      expect(c.enabled, JSON.stringify(bad)).toBe(false);
      expect(c.invalid, JSON.stringify(bad)).toBeTruthy();
    }
  });
});

describe("VerifierSession", () => {
  const text = `HOME=/x\nDB_PASS=${value}\nSMTP_PASS=${other}x\n`;

  it("does nothing when it is off: the engine is never loaded", () => {
    let loads = 0;
    const s = new VerifierSession({
      config: { enabled: false, threshold: "f1" },
      loader: () => {
        loads++;
        throw new Error("no");
      },
    });
    expect(s.active).toBe(false);
    expect(s.accept(text, [])).toEqual([]);
    expect(loads).toBe(0);
  });

  it("returns what the engine accepts as findings of its own rule id, in text order", () => {
    const s = new VerifierSession({ config: ON, loader: acceptAll });
    const found = s.accept(text, []);
    expect(found.map((f) => f.ruleId)).toEqual([VERIFIER_RULE_ID, VERIFIER_RULE_ID]);
    expect(found.map((f) => text.slice(f.start, f.end))).toEqual([value, `${other}x`]);
    expect(found.map((f) => f.line)).toEqual([1, 2]);
    expect(s.stats).toMatchObject({ candidates: 2, judged: 2, accepted: 2, unjudged: 0 });
  });

  it("rejects below the threshold, and never accepts an answer that is not a number", () => {
    const s = new VerifierSession({ config: ON, loader: fakeEngine((c) => (c.value === value ? 0.49 : Number.NaN)) });
    expect(s.accept(text, [])).toEqual([]);
    expect(s.stats).toMatchObject({ judged: 2, accepted: 0 });
  });

  it("leaves a candidate a rule finding overlaps to the rule, unjudged", () => {
    const seen: Array<Record<string, unknown>> = [];
    const s = new VerifierSession({ config: ON, loader: fakeEngine(() => 0.9, seen) });
    const at = text.indexOf(value);
    const found = s.accept(text, [{ ruleId: "some-rule", match: value, secret: value, start: at + 2, end: at + 6, entropy: 3, line: 1 }]);
    expect(found.map((f) => text.slice(f.start, f.end))).toEqual([`${other}x`]);
    expect(seen.map((c) => c.value)).toEqual([`${other}x`]);
    expect(s.stats.covered).toBe(1);
  });

  it("skips values the user allowlisted, and stops entirely when its rule id is allowlisted", () => {
    const s = new VerifierSession({ config: ON, loader: acceptAll, allowlist: { sha256: [sha256(value)] } });
    expect(s.accept(text, []).map((f) => text.slice(f.start, f.end))).toEqual([`${other}x`]);
    expect(s.stats.allowlisted).toBe(1);
    const off = new VerifierSession({ config: ON, loader: acceptAll, allowlist: { rules: [VERIFIER_RULE_ID] } });
    expect(off.active).toBe(false);
    expect(off.accept(text, [])).toEqual([]);
  });

  it("loads the engine only when a string has a candidate to judge", () => {
    let loads = 0;
    const s = new VerifierSession({
      config: ON,
      loader: (p) => {
        loads++;
        return acceptAll(p);
      },
    });
    expect(s.accept("nothing to see here", [])).toEqual([]);
    expect(loads).toBe(0);
    s.accept(text, []);
    s.accept(`token=${value}`, []);
    expect(loads).toBe(1);
  });

  it("stops at its candidate cap and says how many were left unjudged", () => {
    const debug: string[] = [];
    const s = new VerifierSession({ config: ON, loader: acceptAll, maxCandidates: 1, debug: (l) => debug.push(l) });
    expect(s.accept(text, []).length).toBe(1);
    expect(s.accept(`token=${value}`, [])).toEqual([]);
    expect(s.stats).toMatchObject({ judged: 1, unjudged: 1, stopped: "candidate cap" });
    s.report();
    expect(debug.join("\n")).toContain("1 NOT judged (candidate cap)");
    expect(debug.join("\n")).not.toContain(value);
  });

  it("stops when its time budget is spent, judging nothing more", () => {
    const s = new VerifierSession({ config: ON, loader: acceptAll, budgetMs: 0 });
    expect(s.accept(text, [])).toEqual([]);
    expect(s.stats.judged).toBe(0);
    expect(s.stats.stopped).toBe("budget");
  });

  it("judges in a deterministic order: the same text gives the same answers in the same order", () => {
    const a: Array<Record<string, unknown>> = [];
    const b: Array<Record<string, unknown>> = [];
    new VerifierSession({ config: ON, loader: fakeEngine(() => 0.9, a) }).accept(text, []);
    new VerifierSession({ config: ON, loader: fakeEngine(() => 0.9, b) }).accept(text, []);
    expect(a.map((c) => c.offset)).toEqual(b.map((c) => c.offset));
    expect(a.map((c) => c.offset)).toEqual([...a.map((c) => c.offset as number)].sort((x, y) => x - y));
  });

  it("is skipped, never thrown, when the assets are missing or not the pinned files", () => {
    const s = new VerifierSession({ config: ON }); // the real loader, an empty data directory
    expect(s.accept(text, [])).toEqual([]);
    expect(s.stats.stopped).toMatch(/^assets: .* is missing$/);
    expect(s.active).toBe(false);
    mkdirSync(assetDir(), { recursive: true });
    for (const a of ASSETS) writeFileSync(join(assetDir(), a.file), "not the pinned file");
    const t = new VerifierSession({ config: ON });
    expect(t.accept(text, [])).toEqual([]);
    expect(t.stats.stopped).toMatch(/is mismatch$/);
    expect(() => loadEngine("f1")).toThrow(VerifierAssetError);
  });

  it("is skipped when the engine fails to load, or fails on a candidate (what it accepted before stays)", () => {
    const broken = new VerifierSession({
      config: ON,
      loader: () => {
        throw new Error("CompileError: invalid module");
      },
    });
    expect(broken.accept(text, [])).toEqual([]);
    expect(broken.stats.stopped).toBe("engine failed to load");
    let n = 0;
    const flaky = new VerifierSession({
      config: ON,
      loader: fakeEngine(() => {
        if (n++ > 0) throw new Error("RuntimeError: unreachable");
        return 0.9;
      }),
    });
    expect(flaky.accept(text, []).length).toBe(1);
    expect(flaky.stats).toMatchObject({ stopped: "engine error", unjudged: 1 });
    expect(flaky.accept(text, [])).toEqual([]);
  });

  it("does not give the generator a string past its size or regex bounds", () => {
    const s = new VerifierSession({ config: ON, loader: acceptAll });
    expect(s.accept(`${"key".repeat(20_000)}=${value}`, [])).toEqual([]);
    expect(s.accept(`DB_PASS=${value}\n${"a".repeat(1024 * 1024)}`, [])).toEqual([]);
    expect(s.stats.skippedStrings).toEqual({ "generic-keyword bound": 1, "too long": 1 });
    expect(s.accept(text, []).length).toBe(2);
  });

  it("gives the engine the file's path only when it has one", () => {
    const seen: Array<Record<string, unknown>> = [];
    new VerifierSession({ config: ON, loader: fakeEngine(() => 0.1, seen), path: "config/app.env" }).accept(text, []);
    new VerifierSession({ config: ON, loader: fakeEngine(() => 0.1, seen) }).accept(text, []);
    expect(seen.map((c) => c.file)).toEqual(["config/app.env", "config/app.env", null, null]);
    expect(seen.every((c) => c.ext === "" && c.masked === false && !("reported" in c))).toBe(true);
  });
});

describe("repositoryPath", () => {
  it("is the path below the repository, `/`-separated, and nothing for a file outside it", () => {
    const repo = mkdtempSync(join(tmpdir(), "secretgate-repo-"));
    try {
      mkdirSync(join(repo, ".git"));
      mkdirSync(join(repo, "src", "conf"), { recursive: true });
      expect(repositoryPath(join(repo, "src", "conf", "app.yml"), join(repo, "src"))).toBe("src/conf/app.yml");
      expect(repositoryPath("conf/app.yml", join(repo, "src"))).toBe("src/conf/app.yml");
      expect(repositoryPath("/etc/passwd", repo)).toBeUndefined();
      expect(repositoryPath(join(repo, ".."), repo)).toBeUndefined();
      expect(repositoryPath(repo, repo)).toBeUndefined();
      expect(repositoryPath(undefined, repo)).toBeUndefined();
      expect(repositoryPath(42, repo)).toBeUndefined();
    } finally {
      rmSync(repo, { recursive: true, force: true });
    }
  });
});

describe("redactText with the verifier", () => {
  it("redacts an accepted candidate like a finding: placeholder, vault entry under its rule id", () => {
    const vault = new Vault();
    const s = new VerifierSession({ config: ON, loader: acceptAll });
    const r = redactText(`DB_PASS=${value}\n`, vault, "test", {}, (t, f) => s.accept(t, f));
    expect(r.text).toMatch(/^DB_PASS=SECRETGATE_[0-9a-f]{12}\n$/);
    expect(r.findings.map((f) => f.ruleId)).toEqual([VERIFIER_RULE_ID]);
    const placeholder = /SECRETGATE_[0-9a-f]{12}/.exec(r.text)![0];
    expect(vault.secretFor(placeholder)).toBe(value);
    expect(vault.list().map((e) => e.ruleId)).toEqual([VERIFIER_RULE_ID]);
  });

  it("never touches a rule finding: what the rules redact is the same with or without it", () => {
    const text = `token: ${FAKE.githubPat}\napi_key = "${FAKE.genericSecret}"\nDB_PASS=${value}\n`;
    const rules = scan(text, { pragmas: false });
    const without = redactText(text, new Vault(), "test");
    const s = new VerifierSession({ config: ON, loader: acceptAll });
    const withIt = redactText(text, new Vault(), "test", {}, (t, f) => s.accept(t, f));
    for (const f of rules) expect(withIt.findings).toContainEqual(f);
    expect(withIt.findings.filter((f) => f.ruleId !== VERIFIER_RULE_ID)).toEqual(without.findings);
    expect(withIt.text.split("\n").slice(0, 2)).toEqual(without.text.split("\n").slice(0, 2));
    expect(withIt.text).not.toContain(value);
    expect(s.stats.covered).toBeGreaterThan(0);
  });

  it("drops an extra finding that overlaps a rule finding, whatever gave it", () => {
    const text = `token: ${FAKE.githubPat}\n`;
    const at = text.indexOf(FAKE.githubPat);
    const r = redactText(text, new Vault(), "test", {}, () => [{ ruleId: "x", match: "", secret: "", start: at - 3, end: at + 4, entropy: 0, line: 0 }]);
    expect(r.findings.map((f) => f.ruleId)).toEqual(["github-pat"]);
  });

  it("goes on with the rules' findings when the extra findings throw", () => {
    const r = redactText(`token: ${FAKE.githubPat}\n`, new Vault(), "test", {}, () => {
      throw new Error("boom");
    });
    expect(r.findings.map((f) => f.ruleId)).toEqual(["github-pat"]);
    expect(r.text).not.toContain(FAKE.githubPat);
  });

  it("does not take its time from the rules' deadline", () => {
    const busy = (ms: number) => {
      const end = performance.now() + ms;
      while (performance.now() < end) {
        // spin
      }
      return [];
    };
    // 60 ms in the verifier against a 40 ms budget for the rules: the rules
    // still settle (a deadline counted from the start would have expired).
    const r = redactText(`token: ${FAKE.githubPat}\n`, new Vault(), "test", { deadlineMs: 40 }, () => busy(60));
    expect(r.findings.map((f) => f.ruleId)).toEqual(["github-pat"]);
  });
});

describe("assets", () => {
  it("reports each file missing, mismatching or verified, by size and sha256", () => {
    expect(assetStates().map((s) => s.state)).toEqual(["missing", "missing", "missing", "missing"]);
    mkdirSync(assetDir(), { recursive: true });
    writeFileSync(join(assetDir(), "dictionary.txt"), "aaaa\n");
    expect(readAsset("dictionary.txt")).toEqual({ state: "mismatch" });
    // Same size, other bytes.
    writeFileSync(join(assetDir(), "s6-secrets-verify-pico.gguf"), Buffer.alloc(249_984));
    expect(readAsset("s6-secrets-verify-pico.gguf")).toEqual({ state: "mismatch" });
  });

  it("fetch refuses a file that is not the pinned one and writes nothing for it", async () => {
    const lines: string[] = [];
    const urls: string[] = [];
    const fetcher = async (url: string) => {
      urls.push(url);
      return { ok: true, status: 200, url, arrayBuffer: async () => new Uint8Array(16).buffer };
    };
    await expect(fetchAssets((l) => lines.push(l), fetcher)).rejects.toThrow(/could not fetch and verify/);
    expect(urls).toEqual(
      ASSETS.map((a) => `https://huggingface.co/maxgfr/s6-secrets-verify-pico/resolve/9d44c27848bc13ea6015aab13b019710070737a5/engine/${a.file}`),
    );
    expect(lines.every((l) => l.includes("REFUSED") && l.includes("nothing written"))).toBe(true);
    expect(assetStates().map((s) => s.state)).toEqual(["missing", "missing", "missing", "missing"]);
  });

  it("fetch refuses an HTTP error, a redirect off HTTPS, and a network failure", async () => {
    const lines: string[] = [];
    let i = 0;
    const fetcher = async (url: string) => {
      i++;
      if (i === 1) return { ok: false, status: 404, url, arrayBuffer: async () => new ArrayBuffer(0) };
      if (i === 2) return { ok: true, status: 200, url: "http://cdn.example/x", arrayBuffer: async () => new ArrayBuffer(0) };
      throw new Error("ENOTFOUND");
    };
    await expect(fetchAssets((l) => lines.push(l), fetcher)).rejects.toThrow();
    expect(lines[0]).toContain("HTTP 404");
    expect(lines[1]).toContain("off HTTPS");
    expect(lines[2]).toContain("ENOTFOUND");
  });
});
