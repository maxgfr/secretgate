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
  /**
   * Honor inline `gitleaks:allow` / `secretgate:allow` pragmas (default true).
   * Right for scanning your own files; wrong for text on its way to a model —
   * a fetched page or tool output could mark its own secret as allowed.
   */
  pragmas?: boolean;
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
const PLACEHOLDER = /SECRETGATE_[0-9a-f]{12,16}/g;
// What a wider finding may hold around a narrower one and still give way to
// it (see dedupe): less than the shortest value password-assignment itself
// would flag.
const MIN_REMAINDER = 6;
// A placeholder, or one with the stray characters a wider rule captures around
// a token: `key: ghp_….` is redacted to `key: SECRETGATE_….`, and the generic
// rule, which took the dot with the token, must not see a new secret in it.
// Anything longer around the placeholder is material of its own, and is
// redacted (the restore then resolves the placeholder inside the placeholder).
function alreadyRedacted(secret: string): boolean {
  if (!secret.includes("SECRETGATE_")) return false;
  const rest = secret.replace(PLACEHOLDER, "");
  return rest.length < secret.length && rest.length < MIN_REMAINDER;
}

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
  /** same, but for gates that need the surrounding match (e.g. the URL username) */
  postMatch?: (secret: string, match: string) => boolean;
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

// Strip one layer of matching surrounding quotes. Rule capture groups are not
// consistent about them — secretgate's own password-assignment captures the
// bare value, while several gitleaks-derived rules (hashicorp-tf-password
// among them) capture the quotes too. Without this, a placeholder check would
// pass for one rule and fail for the other on identical text.
function unquote(v: string): string {
  const first = v[0];
  if ((first === '"' || first === "'" || first === "`") && v.length >= 2 && v[v.length - 1] === first) {
    return v.slice(1, -1);
  }
  return v;
}

// A value that is ENTIRELY an interpolation is a reference TO a secret, never
// the secret: the real value lives in the environment, the vault or the config
// object. `${VAR}` was already handled, but the anchor demanded a bare word,
// so anything with a dot, a colon or a call slipped through — and
// `apikey: `${this.supabaseKey}`` is what every bundled JS file looks like.
// Each pattern is anchored end to end on purpose: a secret that merely
// CONTAINS `$` or `{` stays a secret.
function looksLikeInterpolation(v: string): boolean {
  return (
    /^\$\{[^{}]*\}$/.test(v) || // ${VAR}, ${this.key}, ${env:DB_PASSWORD}
    /^\$\([^()]*\)$/.test(v) || // $(cat /run/secrets/db)
    /^#\{.*\}$/.test(v) || // Ruby / CoffeeScript #{...}
    /^\{\{.*\}\}$/.test(v) || // Jinja / Go / Handlebars {{ ... }}
    /^\{[A-Za-z_][\w.]*\}$/.test(v) || // Python str.format {settings.api_key}
    /^%\([A-Za-z_]\w*\)[a-z]$/.test(v) || // printf mapping %(db_password)s
    /^<%=?[\s\S]*%>$/.test(v) // ERB / EJS <%= ... %>
  );
}

// Words a documentation value is made of when it only describes what belongs
// there: `SuperSecretToken`, `your-api-key-here`, `not-a-real-password`.
const DESCRIBING_WORDS = new Set([
  ...["a", "an", "the", "my", "your", "our", "this", "that", "is", "not", "no", "real", "super", "very", "top", "some", "any"],
  ...["secret", "secrets", "token", "tokens", "key", "keys", "api", "apikey", "password", "passwd", "pass", "pwd", "passphrase"],
  ...["credential", "credentials", "auth", "access", "private", "client", "user", "admin", "service", "account", "bearer"],
  ...["test", "testing", "example", "sample", "demo", "dummy", "fake", "mock", "foo", "bar", "baz", "value", "string", "text"],
  ...["here", "goes", "change", "me", "changeme", "replace", "insert", "enter", "put", "with", "placeholder", "todo", "default"],
]);

// A value written with letters and separators only, in which EVERY word
// describes a credential or a placeholder. One word from outside the list, a
// digit or a symbol, and it is a value again: a passphrase is not made of
// "secret", "token" and "key" alone.
function onlyDescribesItself(v: string): boolean {
  if (v.length > 64 || !/^[A-Za-z][A-Za-z _.-]*$/.test(v)) return false;
  const words = v.split(/[ _.-]+|(?<=[a-z])(?=[A-Z])/).filter((w) => w !== "");
  return words.length >= 2 && words.every((w) => DESCRIBING_WORDS.has(w.toLowerCase()));
}

function looksLikePlaceholder(raw: string): boolean {
  const v = unquote(raw);
  const low = v.toLowerCase();
  if (PLACEHOLDER_WORDS.has(low)) return true;
  if (/^[*x•.\-_]+$/.test(v)) return true; // masked ***, xxxx, ----
  if (/[*•]{4,}/.test(v)) return true; // partly masked: sk-abcd************
  if (/[A-Z0-9]EXAMPLE$/.test(v)) return true; // the documentation convention AWS set
  if (onlyDescribesItself(v)) return true;
  if (/^\$\{?[a-z_][\w]*\}?$/i.test(v)) return true; // ${VAR} / $VAR interpolation
  if (looksLikeInterpolation(v.trim())) return true;
  if (/^%[a-z_]+%$/i.test(v)) return true; // %VAR%
  if (/^<[^>]+>$/.test(v)) return true; // <your-password>
  if (/^[a-z]+$/.test(low) && new Set(low).size <= 3) return true; // aaaa, abcabc
  return false;
}

// A quoted FILESYSTEM PATH is not a credential. `pwd` sits in the
// password-assignment keyword set because it abbreviates "password", but on a
// developer machine it is far more often POSIX print-working-directory, whose
// output is a path: `pwd = "/private/var/folders/pz/T/TestTmpDir/001"` in Go
// test output was the motivating false positive, being long and mixed-case
// enough to clear the entropy gate. (That example is written as a REAL path
// rather than an elided one on purpose — the repo self-scan reads this
// comment, so an ellipsis here would trip the very rule it documents.)
//
// The test is deliberately narrow, because a secret must not hide behind it:
// the value has to START with a path root, contain at least two separators,
// and consist ONLY of conservative path characters. That last clause is what
// carries the safety — base64/base64url secrets use `+`, `=` and often `%`,
// and real passwords lean on the punctuation this charset excludes. A
// credential that satisfies all three conditions would have to be a
// slash-heavy, punctuation-free string that is already indistinguishable from
// a pathname.
function looksLikeFilesystemPath(raw: string): boolean {
  const v = unquote(raw);
  if (!/^(?:\/|\.\.?\/|~\/|[A-Za-z]:[\\/])/.test(v)) return false;
  const separators = (v.match(/[\\/]/g) ?? []).length;
  if (separators < 2) return false;
  // `:` is admitted for the Windows drive prefix; it costs nothing elsewhere
  // because the root anchor above already had to match, and neither base64 nor
  // base64url uses it.
  return /^[A-Za-z0-9._\-\\/: ]+$/.test(v);
}

// ---------------------------------------------------------------- context
// Filters for the two rules that trust a NAME (`generic-api-key` and
// `password-assignment` flag whatever follows a credential-sounding word).
// They read the name the value is assigned to: the words right before the
// operator, on the same line. Only that name counts — a neighbouring
// `"public_key": …` says nothing about the `"private_key"` next to it.
const NAME_TRUSTING_RULES = new Set(["generic-api-key", "password-assignment"]);

function assignedName(text: string, lineStart: number, valueStart: number): string[] {
  const before = text.slice(Math.max(lineStart, valueStart - 160), valueStart);
  const head = before.replace(/[\s"'`=:>,|?]+$/, "");
  const phrase = /[\w.\- \t]*$/.exec(head)![0];
  return phrase.split(/[ \t]+/).filter((w) => w !== "");
}

const alnum = (v: string): string => v.toLowerCase().replace(/[^a-z0-9]/g, "");

// What a name says is public or a mere identifier: a public key, a PGP key
// (40 hex digits after "GPG key" are its fingerprint), a fingerprint, a cache
// key. A credential word AFTER it takes the exemption back: `fingerprint_api_key`,
// `public_keystore_password` and `gpg_key_passphrase` name secrets.
const PUBLIC_NAME = /(?:pub(?:lic)?[ _.-]?key|(?:gpg|pgp)[ _.-]?key|cache[ _.-]?key|fingerprint)(s?)(?![a-z])/i;
const CREDENTIAL_WORD = /key|api|secret|token|passw|passphrase|private|credential|auth/i;

function namedPublic(name: string[]): boolean {
  // The last few words: "Release GPG key", "Public key ping-sha256".
  const label = name.slice(-3).join(" ");
  const m = PUBLIC_NAME.exec(label);
  return m !== null && !CREDENTIAL_WORD.test(label.slice(m.index + m[0].length));
}

function notASecretInContext(secret: string, name: string[]): boolean {
  // The "value" is the name again: a `…KeysLength` variable that is assigned
  // the `.length` of the keys. (Spelled out, that line would trip gitleaks'
  // generic rule when it scans this file.)
  const last = name[name.length - 1];
  if (last !== undefined && alnum(last).length >= 6 && alnum(last) === alnum(unquote(secret))) return true;
  // Stripe publishable keys are made to be shipped to browsers.
  if (/^pk_(?:test|live)_/.test(unquote(secret))) return true;
  // A PGP fingerprint is hex; anything else after "GPG key" is judged as usual.
  if (/(?:gpg|pgp)[ _.-]?key/i.test(name.slice(-3).join(" ")) && !/^[0-9A-Fa-f \t]+$/.test(unquote(secret))) return false;
  return namedPublic(name);
}

// GitHub tokens are random base62 followed by a checksum. Thirty-odd random
// characters repeat one of them eight times in a row about once in 10^11
// tokens; documentation examples (`ghp_…00000000`) do it by design.
const GITHUB_TOKEN_RULES = new Set(["github-pat", "github-fine-grained-pat", "github-oauth", "github-app-token", "github-refresh-token"]);
const EIGHT_IN_A_ROW = /(.)\1{7}/;

const BUILTIN_RULES: CompiledRule[] = [
  {
    id: "credit-card-number",
    // The lookarounds exclude a DECIMAL context, not just an adjacent digit. On
    // a 42k-file corpus, 231 of 250 card findings were SVG path/ellipse
    // coordinates and the rest geo fixtures: a long fraction satisfies Luhn
    // roughly one time in ten, and vector art emits thousands of them. A PAN is
    // never written immediately after a decimal point, nor immediately before
    // one followed by digits.
    re: /(?<![\d.-])(\d(?:[ -]?\d){12,18})(?![\d-])(?!\.\d)/dg,
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
    // The scheme is bounded and anchored on a non-scheme character: `\b` fired
    // after every `.`/`-`, making `x://a.a.a.…` quadratic (6 s on 160 KB), and
    // the scan deadline is only checked between rules.
    re: /(?<![a-z0-9+.-])[a-z][a-z0-9+.-]{0,31}:\/\/[^\s:/@]{0,256}:([^\s:/@]{3,256})@[^\s]+/dgi,
    keywords: ["://"],
    allowlists: [],
    post: (secret) => !looksLikePlaceholder(secret),
    // The username and the scheme are only knowable from the whole match, so
    // this gate can't live in `post`. 44 of 196 URL-credential findings on the
    // corpus repeated one or the other — the canonical docker-compose and
    // tutorial string, where the password IS `postgres`, `root` or `mongodb`.
    // EQUALITY, never containment: a password that merely BEGINS with the
    // username still fires. (Spelling that counter-example out as a real URL
    // here would trip the repo's own self-scan, which reads this comment.)
    postMatch: (secret, match) => {
      const m = /^([a-z][a-z0-9+.-]*):\/\/([^\s:/@]*):/i.exec(match);
      if (!m) return true;
      const low = secret.toLowerCase();
      const scheme = m[1]!.toLowerCase().split("+")[0]!;
      return low !== m[2]!.toLowerCase() && low !== scheme;
    },
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
    // Whitespace disqualifies the value. gitleaks' generic-api-key stops at
    // `[\w.=-]`, so upstream never matches a spaced value at all; this rule
    // widened the charset to catch punctuation-heavy passwords, and that
    // widening is exactly what let prose in. 155 of 649 findings on the corpus
    // held a space, and every sampled one was a UI label or a sentence
    // (`"password": "Client Secret"` in Airflow's connection-form metadata).
    // The cost is a spaced passphrase, which this rule now leaves to a real
    // password manager — the same trade-off the README already states.
    post: (secret) => !/\s/.test(secret) && !looksLikePlaceholder(secret) && !looksLikeFilesystemPath(secret) && !alreadyRedacted(secret),
  },
  // Credentials a coding agent's .env commonly holds and gitleaks ships no rule
  // for (fed one by one to both engines, gitleaks 8.30 missed all four). The
  // vendor prefix carries the confidence, so no keyword context is required;
  // the length ranges absorb a format revision, the entropy gate a dummy.
  {
    id: "groq-api-key",
    re: /(?<![A-Za-z0-9_])(gsk_[A-Za-z0-9]{48,60})(?![A-Za-z0-9])/dg,
    keywords: ["gsk_"],
    entropy: 3,
    allowlists: [],
  },
  {
    id: "replicate-api-token",
    re: /(?<![A-Za-z0-9_])(r8_[A-Za-z0-9]{35,40})(?![A-Za-z0-9])/dg,
    keywords: ["r8_"],
    entropy: 3,
    allowlists: [],
  },
  {
    id: "xai-api-key",
    re: /(?<![A-Za-z0-9_-])(xai-[A-Za-z0-9]{70,100})(?![A-Za-z0-9])/dg,
    keywords: ["xai-"],
    entropy: 3,
    allowlists: [],
  },
  // Anyone holding the URL can post as the webhook; the token is its last part.
  {
    id: "discord-webhook-url",
    re: /https:\/\/(?:(?:ptb|canary)\.)?discord(?:app)?\.com\/api\/(?:v\d{1,2}\/)?webhooks\/\d{17,20}\/([\w-]{60,80})(?![\w-])/dgi,
    keywords: ["discord"],
    entropy: 3,
    allowlists: [],
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

/** Every rule's pattern, for development tools that need what a match looked
 *  like (scripts/rule-candidates.mjs reads the capture groups). The product
 *  does not call it. */
export function rulePatterns(): Array<{ id: string; re: RegExp; secretGroup?: number }> {
  return COMPILED.map((r) => ({ id: r.id, re: new RegExp(r.re.source, r.re.flags), secretGroup: r.secretGroup }));
}

// The rule database describes secrets, so some regex sources embed literal
// secret-shaped constants (e.g. the Bedrock key's base64 prefix) — scanning
// secretgate's own rule files or shipped bundles would flag its detection
// patterns. Pattern text ships in every copy of secretgate/gitleaks and is
// public by construction, so a candidate found verbatim inside a rule source
// (raw, or JSON-escaped as in the generated table) is never a finding. A real
// credential cannot hide behind this: it would have to BE a substring of a
// fixed public regex, i.e. not be a secret at all.
// All sources joined once by a byte no candidate contains (scanned text with a
// NUL is binary and never reaches a rule), so one search covers them all.
let RULE_SOURCE_BLOB: string | undefined;
function isRuleSourceText(secret: string): boolean {
  RULE_SOURCE_BLOB ??= COMPILED.flatMap((r) => [r.re.source, JSON.stringify(r.re.source).slice(1, -1)]).join("\u0000");
  return !secret.includes("\u0000") && RULE_SOURCE_BLOB.includes(secret);
}

// File names that ARE the finding (e.g. a .p12 bundle) — used by callers that
// scan directories; content scanning ignores them.
/** Rule-independent "this is not a real secret" checks, shared with the
 *  gitleaks hybrid pass: our own placeholders, our own detection patterns, and
 *  obvious placeholder values. */
export function isNonSecret(secret: string): boolean {
  return alreadyRedacted(secret) || isRuleSourceText(secret) || looksLikePlaceholder(secret);
}

/** What `scan` drops because of the rule and of where the value stands, for a
 *  finding another engine made at `start` in `text`. */
export function isNonSecretInContext(text: string, start: number, secret: string, ruleId: string): boolean {
  if (GITHUB_TOKEN_RULES.has(ruleId) && EIGHT_IN_A_ROW.test(secret)) return true;
  if (!NAME_TRUSTING_RULES.has(ruleId)) return false;
  return notASecretInContext(secret, assignedName(text, text.lastIndexOf("\n", start - 1) + 1, start));
}

const PATH_RULES_COMPILED = PATH_RULES.map((r) => ({ id: r.id, re: new RegExp(r.path.source, r.path.flags.replaceAll(/[gy]/g, "")) }));

export function sensitiveFileNameRule(path: string): string | undefined {
  return PATH_RULES_COMPILED.find((r) => r.re.test(path))?.id;
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
  const pragmaLines = cfg.pragmas === false ? new Set<number>() : pragmaAllowedLines(text);
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
      if (alreadyRedacted(secret)) continue; // our own marker
      // Every gate below must pass, so the cheap, rule-specific ones (Luhn,
      // IIN, the URL username) run before the ones that search shared tables.
      if (rule.post && !rule.post(secret)) continue;
      if (rule.postMatch && !rule.postMatch(secret, match[0])) continue;
      if (isRuleSourceText(secret)) continue; // our own detection patterns
      // PLACEHOLDER_WORDS encodes "this string is not a real secret", so it
      // holds no matter which rule matched. It used to be consulted only by
      // password-assignment's `post`, which left every vendor rule to rediscover
      // it: `password = "changeme"` was skipped by password-assignment and then
      // flagged by hashicorp-tf-password — the single most canonical placeholder
      // in existence, redacted out of the user's own file.
      if (looksLikePlaceholder(secret)) continue;
      if (GITHUB_TOKEN_RULES.has(rule.id) && EIGHT_IN_A_ROW.test(secret)) continue;

      const entropy = shannonEntropy(secret);
      if (rule.entropy !== undefined && entropy <= rule.entropy) continue;

      const line = lineAt(starts, start);
      if (pragmaLines.has(line)) continue;
      if (NAME_TRUSTING_RULES.has(rule.id) && notASecretInContext(secret, assignedName(text, starts[line]!, start))) continue;

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

  return dedupe(findings, text);
}

// When two findings' secret spans overlap, one finding is kept and it must
// cover everything either rule flagged: what a dropped finding saw and the
// kept one does not would reach the model unredacted.
//   - One span inside the other: the more specific rule names the secret (a
//     vendor rule beats password-assignment, which beats generic-api-key, then
//     the longer secret wins) — unless the wider one holds more around it than
//     stray punctuation. `api_key = "<key id>:<secret key>"` is one flagged
//     value, and the vendor rule sees only the key id.
//   - Neither inside the other: one finding over both spans.
const specificity = (ruleId: string): number => (ruleId === "generic-api-key" ? 0 : ruleId === "password-assignment" ? 1 : 2);
// Findings are visited by start (longest first), so the kept spans stay sorted
// and disjoint: only the last one kept can reach the next finding.
function dedupe(findings: Finding[], text: string): Finding[] {
  const sorted = [...findings].sort((a, b) => a.start - b.start || b.end - a.end);
  const kept: Finding[] = [];
  for (const f of sorted) {
    const other = kept[kept.length - 1];
    if (other === undefined || f.start >= other.end) {
      kept.push(f);
      continue;
    }
    const preferF = specificity(f.ruleId) > specificity(other.ruleId);
    if (f.end <= other.end) {
      // `f` lies inside `other`.
      const remainder = other.end - other.start - (f.end - f.start);
      if (preferF && remainder < MIN_REMAINDER) kept[kept.length - 1] = f;
      continue;
    }
    const named = preferF ? f : other;
    const secret = text.slice(other.start, f.end);
    kept[kept.length - 1] = { ...named, match: secret, secret, start: other.start, end: f.end, entropy: shannonEntropy(secret), line: other.line };
  }
  return kept;
}
