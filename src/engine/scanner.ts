import { isAllowedPath, isAllowedValue, isDisabledRule, type UserAllowlist } from "./allowlist.js";
import { shannonEntropy } from "./entropy.js";
import { luhnValid } from "./luhn.js";
import { pragmaAllowedLines } from "./pragma.js";
import { GLOBAL_ALLOWLIST, type GenAllowlist, PATH_RULES, RULES } from "./rules.gen.js";

export interface Finding {
  ruleId: string;
  match: string;
  secret: string;
  /** span of the SECRET (not the whole match) in the scanned text */
  start: number;
  end: number;
  entropy: number;
  /** 0-based line index of the secret start */
  line: number;
}

export interface ScanConfig {
  /** enables path-based allowlists (upstream global + user globs) */
  sourcePath?: string;
  allowlist?: UserAllowlist;
  /**
   * Wall-clock budget in ms. Running all rules over a large adversarial payload
   * (every keyword present unlocks all rules) is linear but slow; without a
   * budget a crafted input could stall a hook past the agent's timeout, which
   * is fail-open. When set, scan throws ScanBudgetError past the budget so the
   * hook fails CLOSED (block/deny/withhold). Left unset for the offline `scan`
   * CLI, which may take its time over a whole repo.
   */
  deadlineMs?: number;
}

// Thrown when a scan exceeds its wall-clock budget — callers in the hook path
// treat this like any other failure and fail closed.
export class ScanBudgetError extends Error {
  constructor(ms: number) {
    super(`scan exceeded its ${ms}ms budget`);
    this.name = "ScanBudgetError";
  }
}

// secretgate's own placeholders are ALREADY-redacted text — they must never be
// re-detected as secrets, or the loop breaks: a resent redacted prompt would
// re-block, and writing a placeholder back would be flagged. Kept in sync with
// vault/placeholder.ts PLACEHOLDER_RE (duplicated to keep the engine free of a
// vault dependency).
const PLACEHOLDER_ONLY = /^SECRETGATE_[0-9a-f]{12,16}$/;

interface CompiledAllowlist {
  condition: "AND" | "OR";
  regexTarget: "match" | "line" | "secret";
  regexes: RegExp[];
  stopwords: string[];
  paths: RegExp[];
}

interface CompiledRule {
  id: string;
  re: RegExp;
  entropy?: number;
  secretGroup?: number;
  keywords: string[];
  allowlists: CompiledAllowlist[];
  /** when set, the rule only applies to files whose path matches */
  scope?: RegExp;
  /** extra deterministic gate for built-in rules (e.g. Luhn for cards) */
  post?: (secret: string) => boolean;
}

function compileAllowlist(a: GenAllowlist): CompiledAllowlist {
  return {
    condition: a.condition === "AND" ? "AND" : "OR",
    regexTarget: a.regexTarget ?? "secret",
    regexes: (a.regexes ?? []).map((r) => new RegExp(r.source, r.flags)),
    stopwords: a.stopwords ?? [],
    paths: (a.paths ?? []).map((r) => new RegExp(r.source, r.flags)),
  };
}

// Card numbers: gitleaks ships no PAN rule (too FP-prone on bare regex), so this
// is a secretgate built-in, gated by BOTH a Luhn checksum and a major-network
// IIN prefix — an arbitrary digit run never fires it.
const IIN = /^(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|2(?:22[1-9]|2[3-9]\d|[3-6]\d{2}|7[01]\d|720)\d{12}|3[47]\d{13}|6(?:011|5\d{2})\d{12})$/;

// Placeholder-ish values that appear in docs/examples and are NOT real secrets.
// Applied to the URL-credential and password rules to keep false positives low.
const PLACEHOLDER_WORDS = new Set([
  "password",
  "passwd",
  "pass",
  "secret",
  "changeme",
  "change-me",
  "example",
  "examplepassword",
  "test",
  "testpassword",
  "token",
  "your_password",
  "yourpassword",
  "admin",
  "root",
  "user",
  "username",
  "guest",
  "none",
  "null",
  "redacted",
  "hunter2",
  "placeholder",
]);

function looksLikePlaceholder(v: string): boolean {
  const low = v.toLowerCase();
  if (PLACEHOLDER_WORDS.has(low)) return true;
  if (/^[*x•.\-_]+$/.test(v)) return true; // masked ***, xxxx, ----
  if (/^\$\{?[a-z_][\w]*\}?$/i.test(v)) return true; // ${VAR} / $VAR interpolation
  if (/^%[a-z_]+%$/i.test(v)) return true; // %VAR%
  if (/^<[^>]+>$/.test(v)) return true; // <your-password>
  if (/^[a-z]+$/.test(low) && new Set(low).size <= 3) return true; // aaaa, abcabc
  return false;
}

const BUILTIN_RULES: CompiledRule[] = [
  {
    id: "credit-card-number",
    re: /(?<![\d-])(\d(?:[ -]?\d){12,18})(?![\d-])/dg,
    keywords: [],
    allowlists: [],
    post: (secret) => {
      const digits = secret.replace(/[ -]/g, "");
      return IIN.test(digits) && luhnValid(digits);
    },
  },
  // Credentials embedded in a URL / connection string: scheme://[user]:PASSWORD@host
  // (postgres, mysql, mongodb+srv, redis, amqp, https basic-auth, …). gitleaks
  // ships no generic rule for this and it is an extremely common leak. The
  // captured group is the PASSWORD; a placeholder-ish value is skipped.
  {
    id: "url-credentials",
    re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@]*:([^\s:/@]{3,256})@[^\s]+/dgi,
    keywords: ["://"],
    allowlists: [],
    post: (secret) => !looksLikePlaceholder(secret),
  },
  // QUOTED password / secret assignment with a BROADER value charset than
  // gitleaks' generic-api-key (which stops at `[\w.=-]`, missing `$!@#…`).
  // Quoted-only on purpose: an unquoted value can't be told apart from ordinary
  // code (`secret === undefined`, `apiKey = getKey()`), which floods false
  // positives — quoted values after a secret keyword are almost always literals.
  // Entropy-gated and placeholder-filtered.
  {
    id: "password-assignment",
    re: /(?:password|passwd|pwd|secret|access[_-]?key|api[_-]?key|auth[_-]?token)["']?\s*(?:[:=]|:=|=>)\s*(?:"([^"\n]{6,200})"|'([^'\n]{6,200})'|`([^`\n]{6,200})`)/dgi,
    keywords: ["password", "passwd", "pwd", "secret", "key", "token"],
    entropy: 3,
    allowlists: [],
    post: (secret) => !looksLikePlaceholder(secret) && !/^SECRETGATE_[0-9a-f]{12,16}$/.test(secret),
  },
];

const COMPILED: CompiledRule[] = [
  ...RULES.map((r) => ({
    id: r.id,
    re: new RegExp(r.regex.source, r.regex.flags.includes("g") ? r.regex.flags + "d" : r.regex.flags + "dg"),
    entropy: r.entropy,
    secretGroup: r.secretGroup,
    keywords: r.keywords,
    allowlists: (r.allowlists ?? []).map(compileAllowlist),
    scope: r.scopePath ? new RegExp(r.scopePath.source, r.scopePath.flags) : undefined,
  })),
  ...BUILTIN_RULES,
];

// The rule database describes secrets, so some regex sources embed literal
// secret-shaped constants (e.g. the Bedrock key's base64 prefix) — scanning
// secretgate's own rule files or shipped bundles would flag its detection
// patterns. Pattern text ships in every copy of secretgate/gitleaks and is
// public by construction, so a candidate found verbatim inside a rule source
// (raw, or JSON-escaped as in the generated table) is never a finding. A real
// credential cannot hide behind this: it would have to BE a substring of a
// fixed public regex, i.e. not be a secret at all.
let RULE_SOURCE_TEXTS: string[] | undefined;
function isRuleSourceText(secret: string): boolean {
  RULE_SOURCE_TEXTS ??= COMPILED.flatMap((r) => [r.re.source, JSON.stringify(r.re.source).slice(1, -1)]);
  return RULE_SOURCE_TEXTS.some((s) => s.includes(secret));
}

// File names that ARE the finding (e.g. a .p12 bundle) — used by callers that
// scan directories; content scanning ignores them.
export function sensitiveFileNameRule(path: string): string | undefined {
  return PATH_RULES.find((r) => new RegExp(r.path.source, r.path.flags).test(path))?.id;
}

const GLOBAL_PATHS = GLOBAL_ALLOWLIST.paths.map((p) => new RegExp(p));
const GLOBAL_REGEXES = GLOBAL_ALLOWLIST.regexes.map((r) => new RegExp(r.source, r.flags));
const GLOBAL_STOPWORDS = GLOBAL_ALLOWLIST.stopwords;

function lineStarts(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i++) {
    if (text[i] === "\n") starts.push(i + 1);
  }
  return starts;
}

function lineAt(starts: number[], offset: number): number {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid]! <= offset) lo = mid;
    else hi = mid - 1;
  }
  return lo;
}

function lineText(text: string, starts: number[], line: number): string {
  const start = starts[line]!;
  const end = line + 1 < starts.length ? starts[line + 1]! - 1 : text.length;
  return text.slice(start, end);
}

// Mirrors gitleaks: allowlist REGEXES test the regexTarget-selected string
// (secret by default, or the full match / whole line), while STOPWORDS always
// test the SECRET (lowercased contains). OR — any present criterion allows;
// AND — every present criterion must hold.
function allowlistMatches(a: CompiledAllowlist, secret: string, target: string, sourcePath: string | undefined): boolean {
  const checks: boolean[] = [];
  if (a.regexes.length > 0) checks.push(a.regexes.some((re) => re.test(target)));
  if (a.stopwords.length > 0) {
    const lowerSecret = secret.toLowerCase();
    checks.push(a.stopwords.some((s) => lowerSecret.includes(s)));
  }
  if (a.paths.length > 0) checks.push(sourcePath !== undefined && a.paths.some((re) => re.test(sourcePath)));
  if (checks.length === 0) return false;
  return a.condition === "AND" ? checks.every(Boolean) : checks.some(Boolean);
}

function pickSecret(match: RegExpExecArray, secretGroup: number | undefined): { secret: string; start: number; end: number } {
  const indices = match.indices!;
  if (secretGroup && secretGroup > 0 && match[secretGroup] !== undefined) {
    const [s, e] = indices[secretGroup]!;
    return { secret: match[secretGroup]!, start: s, end: e };
  }
  for (let g = 1; g < match.length; g++) {
    if (match[g] !== undefined && match[g]!.length > 0) {
      const [s, e] = indices[g]!;
      return { secret: match[g]!, start: s, end: e };
    }
  }
  const [s, e] = indices[0]!;
  return { secret: match[0], start: s, end: e };
}

export function scan(text: string, cfg: ScanConfig = {}): Finding[] {
  if (text.length === 0) return [];
  if (cfg.sourcePath) {
    if (GLOBAL_PATHS.some((re) => re.test(cfg.sourcePath!))) return [];
    if (isAllowedPath(cfg.sourcePath, cfg.allowlist)) return [];
  }

  const lower = text.toLowerCase();
  const starts = lineStarts(text);
  const pragmaLines = pragmaAllowedLines(text);
  const findings: Finding[] = [];
  const deadline = cfg.deadlineMs !== undefined ? performance.now() + cfg.deadlineMs : Number.POSITIVE_INFINITY;

  for (const rule of COMPILED) {
    // Check the wall-clock budget between rules (a single rule stays linear;
    // the aggregate over all rules is the cost we bound).
    if (performance.now() > deadline) throw new ScanBudgetError(cfg.deadlineMs!);
    if (isDisabledRule(rule.id, cfg.allowlist)) continue;
    // Scoped rules apply only to matching files; without a path (prompts,
    // tool output) they still run — recall over precision.
    if (rule.scope && cfg.sourcePath && !rule.scope.test(cfg.sourcePath)) continue;
    if (rule.keywords.length > 0 && !rule.keywords.some((k) => lower.includes(k))) continue;

    rule.re.lastIndex = 0;
    for (const match of text.matchAll(rule.re)) {
      const { secret, start, end } = pickSecret(match as RegExpExecArray, rule.secretGroup);
      if (secret.length === 0) continue;
      if (PLACEHOLDER_ONLY.test(secret)) continue; // our own already-redacted marker
      if (isRuleSourceText(secret)) continue; // our own detection patterns
      if (rule.post && !rule.post(secret)) continue;

      const entropy = shannonEntropy(secret);
      if (rule.entropy !== undefined && entropy <= rule.entropy) continue;

      const line = lineAt(starts, start);
      if (pragmaLines.has(line)) continue;

      const fullMatch = match[0];
      let allowed = false;
      for (const a of rule.allowlists) {
        const target = a.regexTarget === "match" ? fullMatch : a.regexTarget === "line" ? lineText(text, starts, line) : secret;
        if (allowlistMatches(a, secret, target, cfg.sourcePath)) {
          allowed = true;
          break;
        }
      }
      if (allowed) continue;
      if (GLOBAL_REGEXES.length > 0 && GLOBAL_REGEXES.some((re) => re.test(secret))) continue;
      if (GLOBAL_STOPWORDS.length > 0 && GLOBAL_STOPWORDS.some((s) => secret.toLowerCase().includes(s))) continue;
      if (isAllowedValue(secret, cfg.allowlist)) continue;

      findings.push({ ruleId: rule.id, match: fullMatch, secret, start, end, entropy, line });
    }
  }

  return dedupe(findings);
}

// When two findings' secret spans overlap, keep the more specific one:
// a named vendor rule beats generic-api-key, then the longer secret wins.
function dedupe(findings: Finding[]): Finding[] {
  const sorted = [...findings].sort((a, b) => a.start - b.start || b.end - a.end);
  const kept: Finding[] = [];
  for (const f of sorted) {
    const clash = kept.findIndex((k) => f.start < k.end && k.start < f.end);
    if (clash === -1) {
      kept.push(f);
      continue;
    }
    const other = kept[clash]!;
    const fGeneric = f.ruleId === "generic-api-key";
    const oGeneric = other.ruleId === "generic-api-key";
    const preferF = (oGeneric && !fGeneric) || (fGeneric === oGeneric && f.end - f.start > other.end - other.start);
    if (preferF) kept[clash] = f;
  }
  return kept.sort((a, b) => a.start - b.start);
}
