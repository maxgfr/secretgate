import { posix } from "node:path";
import type { UserAllowlist } from "./sg-cand-1/allowlist.js";
import { dedupeFindings, type ExtraRule, type MatchGate, scan, type TracedMatch, traceMatches } from "./sg-cand-1/scanner.js";

// The candidate generator `sg-cand-1`, revision 1: the generator the verifier
// (s6-secrets-verify-pico) was trained and measured on, as it was frozen at
// secretgate commit 4e93cfa (`scripts/rule-candidates.mjs --candidates --raw`,
// on branch chore/sg-cand-1). Its engine is NOT secretgate's default engine:
// it runs the copy of that commit's engine under ./sg-cand-1/ (byte for byte,
// see ./sg-cand-1/README.md), so that the rules, gates and dedupe the model
// was measured with do not move when the default engine does.
//
// This file is a port of the raw path of that script's `candidateRecords`:
// what it computes, in the order it computes it, with the same field order in
// each record. Masking (the script's default) is left out: the verifier reads
// real values, and nothing here is written anywhere. The export of this module
// over the CredData training and validation repositories was checked to be
// byte-identical to the frozen files (scripts/verifier-proof.mjs, docs/verifier.md).
//
// The generator, as the script documents it:
//   Rules     every gitleaks-derived rule and every built-in rule, and two
//             rules of its own, `generic-keyword` and `auth-scheme` (below).
//   Stays on  the keyword prefilter; the global path allowlist and the
//             path-scoped rules (only when a source path is given, which the
//             hooks never do); the built-in rules' own gates (Luhn and IIN, the
//             URL username test, no whitespace and no file path in a quoted
//             password); the engine's own material (its SECRETGATE_
//             placeholders, the text of its rules); `dedupe`.
//   Off       the entropy gates; `looksLikePlaceholder`; the per-rule
//             allowlists and stopwords; the global allowlist regexes and
//             stopwords; the filters on what a value says of itself; inline
//             pragmas. Each is recorded in `filters` instead.

export const GENERATOR = "sg-cand-1";
export const REVISION = 1;

// The credential keywords of a `generic-keyword` name.
const KEYWORDS = ["password", "passwd", "pwd", "pass", "secret", "token", "key", "api", "auth", "credential", "cred", "nonce", "salt"];

// generic-keyword, case-insensitive, on one line:
//   1. a name: a maximal run of letters, digits, `_`, `.`, `$`, `-` that
//      contains one of the keywords;
//   2. an optional closing quote of the name (", ' or a backtick), plain or
//      escaped with one backslash, then an optional `]` or `)`;
//   3. a separator, with optional spaces and tabs around it:
//      `:`, `=`, `:=`, `=>`, `==`, `!=`;
//   4. an optional `[`;
//   5. an optional opening quote, plain or escaped with one backslash;
//   6. an optional scheme word, one of Bearer, Basic, Token, Digest,
//      Negotiate, ApiKey, followed by one or more spaces: not part of the value;
//   7. a value of 4 to 256 characters. Quoted, it runs to the same quote;
//      opened by an escaped quote, to the same quote escaped, with no bare
//      quote of that kind before it. Bare, it runs to the first whitespace,
//      `;`, `,` or the end of the line.
const NAME_CHAR = String.raw`[\w.$-]`;
const QUOTES = ['"', "'", "\x60"];
const SEPARATOR = "(?::=|=>|==|!=|:|=)";
const SCHEME_WORDS = "(?:bearer|basic|token|digest|negotiate|apikey) +";
const SCHEME = `(?:${SCHEME_WORDS}|(?!${SCHEME_WORDS}))`;
const VALUE = [
  ...QUOTES.map((q) => `${q}${SCHEME}([^${q}\\r\\n]{4,256})${q}`),
  ...QUOTES.map((q) => `\\\\${q}${SCHEME}([^${q}\\r\\n]{4,256})\\\\${q}`),
  String.raw`(?!\\?["'\x60])${SCHEME}(?!\\?["'\x60])([^\s;,]{4,256})(?![^\s;,])`,
].join("|");

export const GENERIC_KEYWORD: Readonly<ExtraRule> = Object.freeze({
  id: "generic-keyword",
  keywords: KEYWORDS,
  // Judged like the engine's two rules that trust a name, for the `context` flag.
  nameTrusting: true,
  re: new RegExp(
    [
      // biome-ignore lint/complexity/noUselessStringRaw: as the frozen generator writes it
      String.raw`(?<!${NAME_CHAR})${NAME_CHAR}*?(?:${KEYWORDS.join("|")})${NAME_CHAR}*`,
      String.raw`(?:\\?["'\x60])?[\])]?`,
      `[ \\t]*${SEPARATOR}[ \\t]*`,
      String.raw`(?:\[|(?!\[))`,
      `(?:${VALUE})`,
    ].join(""),
    "i",
  ),
});

// auth-scheme: the value after `Bearer` or `Basic`, wherever the header name
// is. 16 to 512 characters of the set; a longer run is not a candidate.
const AUTH_VALUE_CHAR = "[A-Za-z0-9._~+/=-]";
export const AUTH_SCHEME: Readonly<ExtraRule> = Object.freeze({
  id: "auth-scheme",
  keywords: ["bearer", "basic"],
  re: new RegExp(`\\b(?:bearer|basic) +(${AUTH_VALUE_CHAR}{16,512})(?!${AUTH_VALUE_CHAR})`, "i"),
});

// In the order `dedupe` sees them: on the same span, generic-keyword names the
// candidate (it has the name the value is assigned to).
const EXTRA_RULES: ExtraRule[] = [GENERIC_KEYWORD, AUTH_SCHEME];
const EXTRA_IDS = new Set(EXTRA_RULES.map((r) => r.id));

// Gates that still drop a match in candidate mode.
const KEPT_GATES = new Set<MatchGate>(["redacted", "post", "post-match", "rule-source", "user-value"]);
// Gates that are off, and the flag each one sets on the candidate.
const FLAG_OF_GATE: Partial<Record<MatchGate, keyof CandidateFilters>> = {
  entropy: "entropy",
  placeholder: "placeholder",
  "rule-allowlist": "allowlist",
  "global-regex": "allowlist",
  "rule-stopword": "stopword",
  "global-stopword": "stopword",
  "name-context": "context",
  "repeated-character": "context",
  pragma: "pragma",
};
// Ranks `dedupe` knows: generic-api-key 0, password-assignment 1, any other id 2.
const LOWEST_RANK_ID = "generic-api-key";
const TOP_RANK_ID = "sg-cand-1:engine-rule";

export interface CandidateFilters {
  entropy: boolean;
  placeholder: boolean;
  allowlist: boolean;
  stopword: boolean;
  context: boolean;
  pragma: boolean;
}

/** One candidate, as the frozen generator writes it (raw). */
export interface CandidateRecord {
  generator: typeof GENERATOR;
  revision: typeof REVISION;
  file: string | null;
  ext: string;
  rule: string;
  /** 1-based line of the value's first character */
  line: number;
  /** columns in the line, UTF-16 code units; `end` on `endLine` */
  start: number;
  end: number;
  cpStart: number;
  cpEnd: number;
  endLine: number;
  /** offset and length of the value in the text, UTF-16 code units */
  offset: number;
  length: number;
  value: string;
  name: string | null;
  lineText: string;
  lineFrom: number;
  prevLine: string | null;
  nextLine: string | null;
  entropy: number;
  filters: CandidateFilters;
  /** whether the frozen default engine reports an overlapping finding (only with `reported`) */
  reported?: boolean;
  masked: false;
}

export interface GeneratorOptions {
  /** The file's path: recorded, and given to the frozen engine (path allowlist, scoped rules). */
  sourcePath?: string;
  /** Characters kept of each line (1000). */
  maxLine?: number;
  /** Compute `reported` (a second, full scan of the text by the frozen default engine). Default true. */
  reported?: boolean;
  /**
   * The user's allowlist, read by the frozen engine as it reads it: a rule in
   * `rules` does not run (a value only it proposes is no candidate; what
   * another rule proposes on the same span still is), a value in `sha256` is
   * no candidate (its `user-value` gate). The frozen runs had none.
   */
  allowlist?: UserAllowlist;
}

/**
 * The key or variable a value is assigned to: the word right before the
 * operator, on the same line. Undefined when the value is not assigned.
 * (The script's own reading, not the engine's `assignedName`.)
 */
export function assignedName(text: string, valueStart: number): string | undefined {
  const lineStart = text.lastIndexOf("\n", valueStart - 1) + 1;
  const before = text.slice(Math.max(lineStart, valueStart - 200), valueStart);
  const operator = /[\s"'`]*(?:=>|:=|\?=|\|\||[=:>,])[\s"'`=]*(?:(?:bearer|basic|token)[ \t]+)?$/i.exec(before);
  if (!operator) return undefined;
  const left = before.slice(0, operator.index);
  const url = /(?:([\w.$-]+)["'`]?[ \t]*(?:=>|:=|\?=|=|:)[ \t]*["'`]?)?[A-Za-z][A-Za-z0-9+.-]*:\/\/[^\s/@]*$/.exec(left);
  if (url) return url[1];
  const name = /[\w.$-]+$/.exec(left);
  return name ? name[0] : undefined;
}

function lineStartsOf(text: string): number[] {
  const starts = [0];
  for (let i = text.indexOf("\n"); i !== -1; i = text.indexOf("\n", i + 1)) starts.push(i + 1);
  return starts;
}

function lineIndexAt(starts: number[], offset: number): number {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid]! <= offset) lo = mid;
    else hi = mid - 1;
  }
  return lo;
}

// How many Unicode code points `text` holds between two offsets.
function codePoints(text: string, from: number, to: number): number {
  let n = to - from;
  for (let i = from; i < to - 1; i++) {
    const c = text.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = text.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) {
        n--;
        i++;
      }
    }
  }
  return n;
}

const overlaps = (a: { start: number; end: number }, b: { start: number; end: number }): boolean => a.start < b.end && b.start < a.end;

type Live = TracedMatch & { name?: string | undefined; rule?: string };

/** The sg-cand-1 candidates of one text, as raw records (see the top of this file). */
export function candidateRecords(text: string, opts: GeneratorOptions = {}): CandidateRecord[] {
  const maxLine = opts.maxLine ?? 1000;
  const cfg = opts.sourcePath ? { sourcePath: opts.sourcePath } : {};
  const traceCfg = opts.allowlist !== undefined ? { ...cfg, allowlist: opts.allowlist } : cfg;
  const starts = lineStartsOf(text);
  const lineEnd = (i: number): number => {
    const end = i + 1 < starts.length ? starts[i + 1]! - 1 : text.length;
    return end > starts[i]! && text[end - 1] === "\r" ? end - 1 : end;
  };

  const live: Live[] = [];
  for (const m of traceMatches(text, traceCfg, EXTRA_RULES)) {
    const gate = m.gates.find((g) => KEPT_GATES.has(g));
    if (gate === undefined) live.push(m);
  }
  // `dedupe` over the engine's own rules, as `scan` does; then once more with
  // generic-keyword and auth-scheme ranked below every one of them.
  const own = dedupeFindings(
    live.filter((m) => !EXTRA_IDS.has(m.ruleId)),
    text,
  );
  const extra: Live[] = EXTRA_RULES.flatMap((rule) => live.filter((m) => m.ruleId === rule.id)).map((m) =>
    m.ruleId === GENERIC_KEYWORD.id ? { ...m, name: /^[\w.$-]+/.exec(m.match)?.[0] } : m,
  );
  const kept = dedupeFindings<Live>(
    [...own.map((m) => ({ ...m, rule: m.ruleId, ruleId: TOP_RANK_ID })), ...extra.map((m) => ({ ...m, rule: m.ruleId, ruleId: LOWEST_RANK_ID }))],
    text,
  ).sort((a, b) => a.start - b.start);

  const reported = opts.reported === false ? undefined : scan(text, cfg);

  const show = (from: number, to: number): string => text.slice(from, to);
  const cut = (i: number): string | null => (i < 0 || i >= starts.length ? null : show(starts[i]!, Math.min(lineEnd(i), starts[i]! + maxLine)));
  const place = (m: { start: number; end: number }) => {
    const line = lineIndexAt(starts, m.start);
    const endLine = lineIndexAt(starts, Math.max(m.start, m.end - 1));
    return { line, endLine, start: m.start - starts[line]!, end: m.end - starts[endLine]! };
  };

  return kept.map((m) => {
    const at = place(m);
    const filters: CandidateFilters = { entropy: false, placeholder: false, allowlist: false, stopword: false, context: false, pragma: false };
    for (const g of m.gates) {
      const flag = FLAG_OF_GATE[g];
      if (flag) filters[flag] = true;
    }
    // A long line is cut to a window of `maxLine` characters around the value.
    const lineLength = lineEnd(at.line) - starts[at.line]!;
    const inLine = Math.min(m.end - m.start, lineLength - at.start);
    const lineFrom = lineLength <= maxLine ? 0 : Math.max(0, Math.min(at.start - Math.floor((maxLine - Math.min(inLine, maxLine)) / 2), lineLength - maxLine));
    const from = starts[at.line]! + lineFrom;
    const name = m.name ?? assignedName(text, m.start);
    const record: CandidateRecord = {
      generator: GENERATOR,
      revision: REVISION,
      file: opts.sourcePath ?? null,
      ext: opts.sourcePath ? posix.extname(opts.sourcePath).toLowerCase() : "",
      rule: m.rule!,
      line: at.line + 1,
      start: at.start,
      end: at.end,
      cpStart: codePoints(text, starts[at.line]!, m.start),
      cpEnd: codePoints(text, starts[at.endLine]!, m.end),
      endLine: at.endLine + 1,
      offset: m.start,
      length: m.end - m.start,
      value: show(m.start, m.end),
      name: name === undefined || name === null ? null : name,
      lineText: show(from, Math.min(lineEnd(at.line), from + maxLine)),
      lineFrom,
      prevLine: cut(at.line - 1),
      nextLine: cut(at.endLine + 1),
      entropy: Number(m.entropy.toFixed(4)),
      filters,
      ...(reported !== undefined ? { reported: reported.some((f) => overlaps(f, m)) } : {}),
      masked: false,
    };
    return record;
  });
}

/**
 * An estimate, in regex steps, of what `generic-keyword` costs on `text`.
 * Its name is a lazy run of name characters, a keyword, then a greedy run:
 * inside one unbroken run of name characters, every place a keyword starts
 * makes the engine walk to the run's end and back, and then try the
 * separator and the value forms (up to 256 characters each). A run of
 * `keykeykey…` is quadratic (40 KB of it took 0.4 s; 2 MB would take
 * minutes), `key=key=…` costs about a microsecond per keyword, and tool
 * output is text an attacker can write. The verifier skips a text whose
 * estimate is over its limit; the rules are not concerned. On the 8,825
 * files of the census corpus (docs/model-comparison.md) the largest estimate
 * was 8.2 million, for a 1.9 MB file the regex took 7 ms over.
 */
const PER_KEYWORD_STEPS = 1500;
// After the name, `[ \t]*` (and after the separator, `[ \t]*` again) is walked
// for every keyword of the name: a long run of blanks there is paid per
// keyword, and once more by each form of the value tried after a separator.
const PER_BLANK_AFTER_SEPARATOR = 8;

// An EARLY SKIP, not a safety mechanism: the hard bound is the child process
// (src/verifier/child.ts). It errs on the side of skipping.
export function genericKeywordCost(text: string): number {
  const lower = text.toLowerCase();
  // End of the run of name characters each offset is in (its own offset when
  // it is not a name character).
  const n = lower.length;
  const runEnd = new Int32Array(n + 1);
  runEnd[n] = n;
  for (let i = n - 1; i >= 0; i--) {
    const c = lower.charCodeAt(i);
    const name = (c >= 97 && c <= 122) || (c >= 48 && c <= 57) || c === 95 || c === 46 || c === 36 || c === 45 || (c >= 65 && c <= 90);
    runEnd[i] = name ? (i + 1 < n && runEnd[i + 1]! > i + 1 ? runEnd[i + 1]! : i + 1) : i;
  }
  // Length of the run of blanks (spaces, tabs) at each offset.
  const blanks = new Int32Array(n + 1);
  for (let i = n - 1; i >= 0; i--) {
    const c = lower.charCodeAt(i);
    blanks[i] = c === 32 || c === 9 ? blanks[i + 1]! + 1 : 0;
  }
  // What follows a run end: blanks, perhaps a closing quote or bracket, a
  // separator, blanks again.
  const after = (end: number): number => {
    let at = end;
    while (at < n && (lower[at] === '"' || lower[at] === "'" || lower[at] === "`" || lower[at] === "\\" || lower[at] === "]" || lower[at] === ")")) at++;
    let steps = blanks[at]!;
    at += blanks[at]!;
    const sep = /^(?::=|=>|==|!=|:|=)/.exec(lower.slice(at, at + 2));
    if (sep) steps += blanks[at + sep[0].length]! * PER_BLANK_AFTER_SEPARATOR;
    return steps;
  };
  const afterRun = new Map<number, number>();
  let cost = n;
  for (const k of KEYWORDS) {
    for (let at = lower.indexOf(k); at !== -1; at = lower.indexOf(k, at + 1)) {
      const end = runEnd[at]!;
      let tail = afterRun.get(end);
      if (tail === undefined) afterRun.set(end, (tail = after(end)));
      cost += end - at + PER_KEYWORD_STEPS + tail;
    }
  }
  return cost;
}
