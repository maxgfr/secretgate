import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { describe, expect, it } from "vitest";
import { type Finding, scan } from "../../src/engine/scanner.js";

// Opt-in false-positive BENCHMARK over an external corpus of real repositories.
// The always-on `fp-corpus.test.ts` pins a zero-FP budget on a handful of
// distilled fixtures; this one measures the rate on real-world code, which is
// the only way to know whether the firewall is livable.
//
//   SECRETGATE_FP_CORPUS=/path/to/corpus  # dir whose SUBDIRS are repo checkouts
//   SECRETGATE_FP_REPORT=/path/report.json
//   pnpm vitest run tests/engine/fp-corpus-external.test.ts
//
// Skipped (and therefore inert in CI and on other machines) without the corpus
// variable — same pattern as `differential.test.ts`.
const CORPUS = process.env.SECRETGATE_FP_CORPUS;
const REPORT = process.env.SECRETGATE_FP_REPORT;

// Mirrors the CLI's own walk/read filters (src/cli.ts) so the benchmark measures
// what `secretgate scan` would actually look at, not more.
const SKIP_DIRS = new Set([
  ".git",
  "node_modules",
  ".pnpm",
  "dist",
  "coverage",
  ".venv",
  "__pycache__",
  ".next",
  ".nuxt",
  ".svelte-kit",
  ".turbo",
  ".output",
  ".parcel-cache",
  ".astro",
  ".vercel",
]);
const MAX_FILE_BYTES = 2 * 1024 * 1024;

function* walkFiles(root: string): Generator<string> {
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    if (entry.isSymbolicLink()) continue;
    const full = join(root, entry.name);
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) yield* walkFiles(full);
    } else if (entry.isFile()) {
      yield full;
    }
  }
}

function readTextFile(path: string): string | undefined {
  const stats = statSync(path);
  if (stats.size === 0 || stats.size > MAX_FILE_BYTES) return undefined;
  const buf = readFileSync(path);
  if (buf.subarray(0, 8192).includes(0)) return undefined;
  return buf.toString("utf8");
}

interface Row {
  repo: string;
  path: string;
  line: number;
  ruleId: string;
  entropy: number;
  length: number;
  sha256: string;
  /** the source line with the secret span replaced by a mask — see maskLine */
  context: string;
  /** derived descriptors of the secret — see describeSecret */
  tags: string[];
}

// Classifying 2000+ findings needs to know what KIND of string matched, but the
// value itself must not leave the machine. These booleans carry the signal that
// decides true-vs-false positive — a lowercase word, a UUID, a hex digest, a
// shell/template interpolation — without carrying the string.
function describeSecret(secret: string, fullMatch: string): string[] {
  const tags: string[] = [];
  const s = secret.replace(/^["'`]|["'`]$/g, "");
  // Plain words separated by single spaces: a UI label or a sentence, not a
  // credential (`"password": "Client Secret"` in a form-relabeling map).
  if (/^[A-Za-z]+(?: [A-Za-z]+)+$/.test(s)) tags.push("titlewords");
  // scheme://user:PASSWORD@host where the password repeats the username or the
  // scheme — the canonical doc/dev connection string (`postgres:postgres@`).
  const url = /^([a-z][a-z0-9+.-]*):\/\/([^\s:/@]*):/i.exec(fullMatch);
  if (url) {
    if (url[2] && url[2].toLowerCase() === s.toLowerCase()) tags.push("pwEqualsUser");
    if (url[1] && s.toLowerCase() === url[1].toLowerCase().split("+")[0]) tags.push("pwEchoesScheme");
  }
  if (/^[a-f0-9]+$/i.test(s)) tags.push("hex");
  if (/^[0-9\s.-]+$/.test(s)) tags.push("digits");
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s)) tags.push("uuid");
  if (/^[a-z][a-z0-9_.-]*$/.test(s)) tags.push("wordish");
  if (/\s/.test(s)) tags.push("space");
  if (/^\$[({]|[${]/.test(s) && /[$][{(]?\w/.test(s)) tags.push("interpolation");
  if (/^<.*>$|^\{\{.*\}\}$/.test(s)) tags.push("template");
  if (
    /(test|fake|dummy|example|sample|foo|bar|baz|change|placeholder|redact|xxx|abc123|password|passwd|secret|token|apikey|api_key|admin|localhost|your|my-|-here|not-?real|invalid)/i.test(
      s,
    )
  )
    tags.push("fakeish");
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(s) && s.length % 4 === 0 && s.length >= 16) tags.push("base64ish");
  if (/^[\w.-]+\/[\w./-]+$/.test(s)) tags.push("pathish");
  if (new Set(s).size <= 4) tags.push("lowvariety");
  return tags;
}

// Triage needs the SURROUNDING code (is this a lockfile hash? a doc example? a
// real key?) but must not carry the value itself: a corpus can contain live
// credentials, and this report is read by a human — and, on this project, by an
// LLM. Length and hash live in their own fields, so the inline mask is `xxxx…`,
// which `looksLikePlaceholder` recognises: a masked line must not itself be
// detectable, or reading the report re-triggers the very rule it documents (the
// first version used `‹len=N sha=…›` and got redacted by the installed hook).
const MASK = "xxxxxxxx";

function maskLine(text: string, f: Finding): string {
  const lineStart = text.lastIndexOf("\n", f.start - 1) + 1;
  const lineEndRaw = text.indexOf("\n", f.end);
  const lineEnd = lineEndRaw === -1 ? text.length : lineEndRaw;
  const before = text.slice(lineStart, f.start).slice(-90);
  const after = text.slice(f.end, lineEnd).slice(0, 90);
  return (before + MASK + after).replace(/\s+/g, " ").trim();
}

describe.skipIf(!CORPUS)("false-positive benchmark over an external corpus", () => {
  it("scans the corpus on both surfaces and writes a masked report", { timeout: 30 * 60 * 1000 }, () => {
    const repos = readdirSync(CORPUS!, { withFileTypes: true })
      .filter((e) => e.isDirectory())
      .map((e) => e.name)
      .sort();
    expect(repos.length, "corpus dir has no repo subdirectories").toBeGreaterThan(0);

    // Surface A = `secretgate scan <dir>`: sourcePath set, so upstream path
    // allowlists (lockfiles, go.sum, minified bundles, images) apply.
    // Surface B = the HOOK path: a prompt paste or tool output, scanned with
    // NO path, hence no path allowlist. B is the worst case and the one that
    // blocks a user's prompt.
    const surfaceA: Row[] = [];
    const surfaceB: Row[] = [];
    const perRepo: Record<string, { files: number; bytes: number; a: number; b: number; filesWithB: number }> = {};

    for (const repo of repos) {
      const root = join(CORPUS!, repo);
      const stats = { files: 0, bytes: 0, a: 0, b: 0, filesWithB: 0 };
      for (const file of walkFiles(root)) {
        const text = readTextFile(file);
        if (text === undefined) continue;
        const rel = relative(root, file);
        stats.files++;
        stats.bytes += text.length;

        const b = scan(text);
        for (const f of b)
          surfaceB.push({
            repo,
            path: rel,
            line: f.line + 1,
            ruleId: f.ruleId,
            entropy: Number(f.entropy.toFixed(3)),
            length: f.secret.length,
            sha256: createHash("sha256").update(f.secret).digest("hex").slice(0, 12),
            context: maskLine(text, f),
            tags: describeSecret(f.secret, f.match),
          });
        stats.b += b.length;
        if (b.length > 0) stats.filesWithB++;

        const a = scan(text, { sourcePath: rel });
        for (const f of a)
          surfaceA.push({
            repo,
            path: rel,
            line: f.line + 1,
            ruleId: f.ruleId,
            entropy: Number(f.entropy.toFixed(3)),
            length: f.secret.length,
            sha256: createHash("sha256").update(f.secret).digest("hex").slice(0, 12),
            context: maskLine(text, f),
            tags: describeSecret(f.secret, f.match),
          });
        stats.a += a.length;
      }
      perRepo[repo] = stats;
      console.log(
        `${repo.padEnd(14)} files=${String(stats.files).padStart(6)} A=${String(stats.a).padStart(5)} B=${String(stats.b).padStart(5)} filesWithB=${stats.filesWithB}`,
      );
    }

    const byRule = (rows: Row[]): Record<string, number> => {
      const out: Record<string, number> = {};
      for (const r of rows) out[r.ruleId] = (out[r.ruleId] ?? 0) + 1;
      return Object.fromEntries(Object.entries(out).sort((x, y) => y[1] - x[1]));
    };

    const totals = Object.values(perRepo).reduce(
      (acc, s) => ({ files: acc.files + s.files, bytes: acc.bytes + s.bytes, filesWithB: acc.filesWithB + s.filesWithB }),
      { files: 0, bytes: 0, filesWithB: 0 },
    );
    const report = {
      corpus: CORPUS,
      totals: {
        ...totals,
        surfaceA: surfaceA.length,
        surfaceB: surfaceB.length,
        surfaceBPer1000Files: Number(((surfaceB.length / totals.files) * 1000).toFixed(2)),
        filesBlockedPer1000: Number(((totals.filesWithB / totals.files) * 1000).toFixed(2)),
      },
      perRepo,
      byRuleA: byRule(surfaceA),
      byRuleB: byRule(surfaceB),
      surfaceA,
      surfaceB,
    };

    console.log(`\nTOTAL files=${totals.files} A=${surfaceA.length} B=${surfaceB.length} filesWithB=${totals.filesWithB}`);
    console.log(`byRuleB: ${JSON.stringify(report.byRuleB)}`);

    if (REPORT) {
      mkdirSync(dirname(REPORT), { recursive: true });
      writeFileSync(REPORT, `${JSON.stringify(report, null, 2)}\n`);
      expect(existsSync(REPORT)).toBe(true);
    }
    // The benchmark MEASURES; it does not assert a budget. Asserting here
    // would make the number invisible the moment it regressed.
    expect(totals.files).toBeGreaterThan(0);
  });
});
