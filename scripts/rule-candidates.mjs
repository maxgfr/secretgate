#!/usr/bin/env node
// Candidate export: one JSON line per rule candidate, with what the scanner
// knows at match time. Dev-only (not in the bundle): it builds the data a later
// model needs to judge a rule candidate in its context and answer P(real
// secret). The rule side is secretgate's own scanner, imported from the
// TypeScript sources through Node's type stripping (Node >= 22.18).
//
//   node scripts/rule-candidates.mjs <dir|file>... [--files-from LIST] [--base DIR]
//     [--out FILE] [--candidates [--dropped FILE] [--max-line 1000]] [--generic]
//     [--context 160] [--all-text] [--max-bytes 2097152] [--stats FILE] [--raw]
//
// Three modes: the engine's findings as they are (default), the same plus a
// loose first take on high-recall candidates (--generic), and the candidate
// generator `sg-cand-1` (--candidates). Nothing here touches the network.
//
// ---------------------------------------------------------------- --candidates
// The generator `sg-cand-1`: the engine with the filters a verifier is meant
// to replace turned off, plus one keyword rule. It runs the engine's own
// matching loop (`traceMatches` in src/engine/scanner.ts), with the file's
// path as source path.
//
//   Rules     every gitleaks-derived rule and every built-in rule, and two
//             rules of its own, `generic-keyword` and `auth-scheme` (below).
//   Stays on  the keyword prefilter; the global path allowlist (a file under
//             it gives no candidate) and the path-scoped rules; the built-in
//             rules' own gates (Luhn and IIN for card numbers, the URL
//             username test, no whitespace and no file path in a quoted
//             password); the engine's own material (its SECRETGATE_
//             placeholders, the text of its rules); `dedupe`.
//   Off       the entropy gates; `looksLikePlaceholder`, also where a
//             built-in rule's gate calls it; the per-rule allowlists and
//             stopwords; the global allowlist regexes and stopwords; the
//             filters on what a value says of itself (a name that calls it
//             public, a value that repeats its name, a publishable key, a
//             GitHub token with one character eight times in a row); inline
//             pragmas. Each is recorded in `filters` instead.
//
//   This is revision 1 of the generator, its single revision (the first
//   state read name, quote, separator, quote, value, and had no auth-scheme).
//
//   generic-keyword, case-insensitive, on one line:
//     1. a name: a maximal run of letters, digits, `_`, `.`, `$`, `-` that
//        contains one of password, passwd, pwd, pass, secret, token, key, api,
//        auth, credential, cred, nonce, salt;
//     2. an optional closing quote of the name (", ' or a backtick), plain or
//        escaped with one backslash, then an optional `]` or `)`;
//     3. a separator, with optional spaces and tabs around it:
//        `:`, `=`, `:=`, `=>`, `==`, `!=`;
//     4. an optional `[`;
//     5. an optional opening quote, plain or escaped with one backslash;
//     6. an optional scheme word, one of Bearer, Basic, Token, Digest,
//        Negotiate, ApiKey, followed by one or more spaces: it is not part of
//        the value;
//     7. a value of 4 to 256 characters. Quoted, it runs to the same quote;
//        opened by an escaped quote, to the same quote escaped, with no bare
//        quote of that kind before it. Bare, it runs to the first whitespace,
//        `;`, `,` or the end of the line.
//   Narrow readings: nothing but what is listed may stand between two steps
//   (no space between the name's quote and `]`, none after `[`). An optional
//   element that is there is taken as that element, never as the start of the
//   value: after `[`, the value does not fall back to a bare `[…`; a bare
//   value cannot begin with a quote, escaped or not; a scheme word followed
//   by a space is never the value, so a scheme with nothing of 4 characters
//   after it gives no candidate. A longer or shorter text is not a candidate.
//
//   auth-scheme, case-insensitive: the word Bearer or Basic at a word
//   boundary, one or more spaces, then a value of 16 to 512 characters among
//   ASCII letters, digits and `. _ ~ + / = -`. The value is the whole run of
//   such characters: a longer run is not a candidate. It covers a header value
//   whose header name is on another line.
//
//   In `dedupe` both rank below every other rule: where another rule's value
//   overlaps theirs, the other rule names the candidate (and the span is the
//   engine's: the narrower value when at most 5 characters stand around it,
//   else the wider one; one span over both when neither holds the other).
//   Between the two, the wider value wins, and generic-keyword on the same
//   span.
//
// Each line of the export is one candidate:
//   generator  "sg-cand-1"
//   revision   1
//   file       the file's path as listed or walked (below --base when given)
//   ext        its extension, lower-case, with the dot ("" when none)
//   rule       rule id
//   line       1-based line of the value's first character (lines end at "\n")
//   start,end  columns of the value in its line: 0-based, end exclusive, in
//              UTF-16 code units (JavaScript string indices)
//   cpStart,cpEnd  the same columns in Unicode code points (Python indices)
//   endLine    1-based line of the value's last character; `end` and `cpEnd`
//              are columns of that line (it is `line` unless the value spans
//              lines, as a private key does)
//   offset     offset of the value in the file's text; length: its length
//              (both in UTF-16 code units)
//   value      the value
//   name       the key or variable name: for generic-keyword the name it
//              matched, else the word before the operator; null when none.
//              Masked but for its credential keywords unless --raw
//   lineText   the value's first line, without its line ending. A line longer
//              than --max-line is cut to a window around the value, and
//              lineFrom is the column where the window starts (0 otherwise)
//   prevLine   the line before `line`, nextLine the line after `endLine`,
//              each cut to its first --max-line characters; null at the
//              file's ends
//   entropy    Shannon entropy of the REAL value, bits per character, as the
//              engine computes it
//   filters    which of the filters that are off the default engine would
//              have dropped this match for:
//                entropy      at or under its rule's entropy threshold
//                placeholder  `looksLikePlaceholder`
//                allowlist    a per-rule allowlist regex or path, or a global
//                             allowlist regex
//                stopword     a per-rule or a global stopword
//                context      what the value says of itself (see "Off")
//                pragma       an allow pragma on or above the line
//              They are those of the match that names the candidate.
//              generic-keyword and auth-scheme have no threshold, allowlist
//              or stopword of their own: only placeholder, the global lists
//              and pragma can be set on them, and context on generic-keyword.
//   reported   whether the default engine (`scan`, same text, same path)
//              reports a finding that overlaps the value
//   masked     whether value, name, lineText, prevLine and nextLine are
//              masked (see "masking" below)
//
// --dropped FILE writes one line per match a kept gate dropped: file, rule,
// gate, line, start, end, endLine, offset, length. Never the value.
// --stats FILE writes the run's counts: files, lines, candidates by rule.
// --files-from LIST reads the files to scan from LIST, one path per line;
// --base DIR is where the paths (listed or given) are read from.
//
// ---------------------------------------------------------------- default and --generic
// Each line:
//   file      path as given on the command line, joined with the path below it
//   mode      "rule" (a finding of the engine) or "generic" (see --generic)
//   rule      rule id; "candidate:assignment" / "candidate:auth-header" for generic
//   line      1-based line of the value
//   start,end offsets of the value in the file's text (UTF-16 code units, as
//             JavaScript strings count), and its length
//   match     offsets of the whole regex match; groups: offsets of every
//             capture group (null for one that did not take part)
//   name      the key or variable the value is assigned to, when one can be
//             isolated (the word before the operator on the same line)
//   entropy   Shannon entropy of the REAL value, bits per character
//   classes   how many lower-case, upper-case, digit and other characters it has
//   context   {start, before, value, after}: the value and up to --context
//             characters on each side, cut at the file's ends
//   masked    whether `context` and `name` are masked
//
// --generic adds high-recall candidates the rules do not propose: any value
// assigned to a name that sounds like a credential (password, secret, token,
// key, auth…), whatever its entropy, quoting or stopwords, and the value of an
// Authorization-style header. Scanned like tool output: no source path, no
// pragmas. It is NOT the rule of sg-cand-1.
//
// ---------------------------------------------------------------- masking
// MASKED BY DEFAULT, in every mode. In a masked export EVERY letter and digit
// of every text field (the value, its line, the lines around it, the context
// window) is replaced by another one of the same class: a lower-case letter by
// a lower-case letter, a digit by a digit; punctuation and spacing stay.
// Length and shape survive, the text does not. Masking only the values a rule
// proposes would not do: a secret no rule proposes often sits next to one
// that a rule found (the second column of a credentials file, the rest of a
// command line), and it would be written in clear.
//
// One thing stays readable: inside the record's own `name`, the credential
// keywords of sg-cand-1 (password, passwd, pwd, pass, secret, token, key, api,
// auth, credential, cred, nonce, salt). `DB_PASSWORD` is written `XY_PASSWORD`,
// in the `name` field and where the name stands on the value's line. These
// words are public, and they are what the rule looked for. Every other part of
// a name is masked: the word before an operator can be a value too.
//
// The mapping is keyed by a random key drawn for the run and never written. A
// candidate's value is masked as one value, so it reads the same wherever the
// export repeats it (a first pass over all the files collects the values);
// every other run of letters and digits is masked on its own. --raw writes
// real text and real values; it has to be asked for, and its file is not to be
// committed. --out is always left readable by its owner only (0600).
import { createHmac, randomBytes } from "node:crypto";
import { closeSync, fchmodSync, openSync, readdirSync, readFileSync, statSync, writeFileSync, writeSync } from "node:fs";
import * as nodeModule from "node:module";
import { extname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

// ---------------------------------------------------------------- masking

const LOWER = "abcdefghijklmnopqrstuvwxyz";
const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGIT = "0123456789";
const classOf = (c) => (c >= "a" && c <= "z" ? LOWER : c >= "A" && c <= "Z" ? UPPER : c >= "0" && c <= "9" ? DIGIT : undefined);

// Letters and digits outside ASCII (a password can hold them): the characters
// of the same Unicode category that sit near it in its block.
const CATEGORIES = [/\p{Lu}/u, /\p{Ll}/u, /\p{L}/u, /\p{N}/u];
const isSurrogate = (code) => code >= 0xd800 && code <= 0xdfff;
function neighbours(c) {
  const code = c.charCodeAt(0);
  if (code < 0x80 || isSurrogate(code)) return undefined;
  const category = CATEGORIES.find((re) => re.test(c));
  if (!category) return undefined;
  const out = [];
  for (let d = -40; d <= 40; d++) {
    const other = code + d;
    if (d !== 0 && other >= 0x80 && other <= 0xffff && !isSurrogate(other) && category.test(String.fromCharCode(other))) out.push(String.fromCharCode(other));
  }
  return out.length > 0 ? out : undefined;
}

// A letter or a digit outside the Basic Multilingual Plane (two code units):
// a fixed stand-in of the same kind, or the second one when it is the first.
const ASTRAL = [
  [/\p{L}/u, "\u{1D4B3}", "\u{1D4B4}"],
  [/\p{N}/u, "\u{1D7D8}", "\u{1D7D9}"],
];

/** A fresh key for one export. */
export const newMaskKey = () => randomBytes(32);

/**
 * `value` with every letter and digit replaced by a DIFFERENT character of the
 * same class; everything else is kept (punctuation, symbols). Same length.
 * Deterministic for a given key.
 */
export function maskValue(value, key) {
  let stream = Buffer.alloc(0);
  let block = 0;
  let out = "";
  for (let i = 0; i < value.length; i++) {
    const c = value[i];
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff && i + 1 < value.length) {
      const pair = value.slice(i, i + 2);
      const kind = ASTRAL.find(([re]) => re.test(pair));
      if (kind) {
        out += pair === kind[1] ? kind[2] : kind[1];
        i++;
        continue;
      }
    }
    const alphabet = classOf(c);
    const near = alphabet === undefined ? neighbours(c) : undefined;
    if (alphabet === undefined && near === undefined) {
      out += c;
      continue;
    }
    while (i >= stream.length) {
      stream = Buffer.concat([stream, createHmac("sha256", key).update(`${block++}:${value}`).digest()]);
    }
    if (near !== undefined) {
      out += near[stream[i] % near.length];
      continue;
    }
    // One of the other characters of the class, never the original.
    const others = alphabet.length - 1;
    const at = (alphabet.indexOf(c) + 1 + (stream[i] % others)) % alphabet.length;
    out += alphabet[at];
  }
  return out;
}

/** An index of values for `maskKnown`, by their first 6 characters. Values
 *  shorter than 8 characters are left out: they are words, not secrets. */
export function valueIndex(values) {
  const index = new Map();
  for (const v of new Set(values)) {
    if (v.length < 8) continue;
    const k = v.slice(0, 6);
    if (!index.has(k)) index.set(k, []);
    index.get(k).push(v);
  }
  for (const list of index.values()) list.sort((a, b) => b.length - a.length);
  return index;
}

/** `text` with every verbatim occurrence of an indexed value masked. */
export function maskKnown(text, index, key) {
  if (!index || index.size === 0) return text;
  let out = "";
  let from = 0;
  for (let i = 0; i + 6 <= text.length; i++) {
    const value = index.get(text.slice(i, i + 6))?.find((v) => text.startsWith(v, i));
    if (value === undefined) continue;
    out += text.slice(from, i) + maskValue(value, key);
    from = i + value.length;
    i = from - 1;
  }
  return out + text.slice(from);
}

// One mask per word and per key: a context repeats its words.
const WORD = /[\p{L}\p{N}]+/gu;
const wordMasks = new Map();
function maskWords(text, key) {
  const k = typeof key === "string" ? key : key.toString("latin1");
  let masks = wordMasks.get(k);
  if (masks === undefined || masks.size > 200000) {
    if (wordMasks.size > 8) wordMasks.clear();
    wordMasks.set(k, (masks = new Map()));
  }
  return text.replace(WORD, (w) => {
    let masked = masks.get(w);
    if (masked === undefined) masks.set(w, (masked = maskValue(w, key)));
    return masked;
  });
}

/**
 * `text` with EVERY letter and digit masked: an indexed value as one value
 * (so that it reads the same wherever the export repeats it), and every other
 * run of letters and digits on its own. What no rule proposed is masked too:
 * a secret often sits next to the one a rule found.
 */
export function maskAll(text, index, key) {
  if (!index || index.size === 0) return maskWords(text, key);
  let out = "";
  let from = 0;
  for (let i = 0; i + 6 <= text.length; i++) {
    const value = index.get(text.slice(i, i + 6))?.find((v) => text.startsWith(v, i));
    if (value === undefined) continue;
    out += maskWords(text.slice(from, i), key) + maskValue(value, key);
    from = i + value.length;
    i = from - 1;
  }
  return out + maskWords(text.slice(from), key);
}

// The only words a masked record keeps readable: these, inside its own name.
// They are public, and the rule that made the record looked for them.
const KEYWORDS = ["password", "passwd", "pwd", "pass", "secret", "token", "key", "api", "auth", "credential", "cred", "nonce", "salt"];
const KEYWORD = new RegExp(KEYWORDS.join("|"), "gi");

/** A key or variable name, masked but for the credential keywords it holds:
 *  `DB_PASSWORD` keeps its shape and `PASSWORD`. */
export function maskName(name, key) {
  let out = maskValue(name, key);
  for (const m of name.matchAll(KEYWORD)) out = out.slice(0, m.index) + m[0] + out.slice(m.index + m[0].length);
  return out;
}

export function charClasses(value) {
  const n = { lower: 0, upper: 0, digit: 0, other: 0 };
  for (const c of value) {
    const a = classOf(c);
    n[a === LOWER ? "lower" : a === UPPER ? "upper" : a === DIGIT ? "digit" : "other"]++;
  }
  return n;
}

export function shannonEntropy(value) {
  if (value.length === 0) return 0;
  const counts = new Map();
  for (const c of value) counts.set(c, (counts.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) h -= (n / value.length) * Math.log2(n / value.length);
  return h;
}

// ---------------------------------------------------------------- names

/**
 * The key or variable a value is assigned to: the word right before the
 * operator, on the same line (`aws_secret_key` in `aws_secret_key = "…"`,
 * `token` in `{"token": "…"}`). Undefined when the value is not assigned.
 */
export function assignedName(text, valueStart) {
  const lineStart = text.lastIndexOf("\n", valueStart - 1) + 1;
  const before = text.slice(Math.max(lineStart, valueStart - 200), valueStart);
  const operator = /[\s"'`]*(?:=>|:=|\?=|\|\||[=:>,])[\s"'`=]*(?:(?:bearer|basic|token)[ \t]+)?$/i.exec(before);
  if (!operator) return undefined;
  const left = before.slice(0, operator.index);
  // A password inside a URL (scheme, "://", user, ":", VALUE, "@", host): the
  // word before the colon is the user. The name is what the URL itself is
  // assigned to.
  const url = /(?:([\w.$-]+)["'`]?[ \t]*(?:=>|:=|\?=|=|:)[ \t]*["'`]?)?[A-Za-z][A-Za-z0-9+.-]*:\/\/[^\s/@]*$/.exec(left);
  if (url) return url[1];
  const name = /[\w.$-]+$/.exec(left);
  return name ? name[0] : undefined;
}

// ---------------------------------------------------------------- generic candidates

// A name that sounds like a credential. Deliberately wide: this mode is for
// recall, and a model judges the candidates afterwards. Only the names that
// were wrong every time on real files are left out: `author` (auth),
// `minipass` and `bypass` (pass), `…_signature_…` (compiler messages).
const CREDENTIAL_NAME =
  /passw(?:or)?d|passwd|passphrase|passcode|(?:^|[_.-])pass$|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential|auth(?!or)|bearer|session[_-]?(?:id|token|key)|cookie|dsn$|key$/i;
// name <operator> value: a quoted value of any content, or a bare one up to
// the next space, quote, comma or semicolon.
const ASSIGNMENT = /([A-Za-z_$][\w.$-]{0,80})["'`]?[ \t]*(?:=>|:=|\?=|=|:)[ \t]*(?:"([^"\n]{4,200})"|'([^'\n]{4,200})'|`([^`\n]{4,200})`|([^\s"'`,;]{6,200}))/dg;
// Authorization: Bearer <value>, X-Api-Key: <value>, Cookie: <value>…
const AUTH_HEADER = /\b(authorization|proxy-authorization|x-api-key|x-auth-token|x-access-token|api-key|cookie)["']?[ \t]*[:=][ \t]*["']?(?:(?:bearer|basic|token|digest|apikey)[ \t]+)?([^\s"'`,;]{8,400})/dgi;

// A bare (unquoted) value that is ordinary code or a type: an identifier path
// with no digit (`process.env.API_KEY`, `string`, `Token`), a call, an index,
// a boolean or a number.
function bareValueIsCode(v) {
  return /^[A-Za-z_$][A-Za-z_$.]*$/.test(v) || /[()[\]{}<>]/.test(v) || /^(?:true|false|null|undefined|none|nil|\d+(?:\.\d+)?)$/i.test(v);
}

/**
 * High-recall candidates: values assigned to credential-sounding names and
 * authorization-style headers. Returns `{start, end, kind, name, match}` with
 * offsets into `text`; `match` is the whole match's `[start, end]`.
 */
export function genericCandidates(text) {
  const out = [];
  for (const m of text.matchAll(ASSIGNMENT)) {
    const name = m[1];
    if (!CREDENTIAL_NAME.test(name)) continue;
    const group = [2, 3, 4, 5].find((g) => m[g] !== undefined);
    if (group === 5 && bareValueIsCode(m[5])) continue;
    const [start, end] = m.indices[group];
    out.push({ start, end, kind: "candidate:assignment", name, match: m.indices[0], groups: m.indices.slice(1).map((g) => g ?? null) });
  }
  for (const m of text.matchAll(AUTH_HEADER)) {
    const [start, end] = m.indices[2];
    out.push({ start, end, kind: "candidate:auth-header", name: m[1], match: m.indices[0], groups: m.indices.slice(1).map((g) => g ?? null) });
  }
  // Longest first at each start; one that lies inside another adds nothing.
  out.sort((a, b) => a.start - b.start || b.end - a.end);
  return out.filter((c, i) => !out.some((o, j) => j !== i && o.start <= c.start && o.end >= c.end && (o.end - o.start > c.end - c.start || j < i)));
}

// ---------------------------------------------------------------- candidates of one text

const overlaps = (a, b) => a.start < b.end && b.start < a.end;

// The regex match behind a finding: the scanner returns the value's span, and
// the rule's pattern, run again, gives the whole match and its groups. A
// finding the scanner merged from two overlapping ones has no single match.
function matchBehind(text, finding, pattern) {
  if (!pattern) return undefined;
  const flags = [...new Set(`${pattern.re.flags}dg`)].join("");
  const re = new RegExp(pattern.re.source, flags);
  // Start a little before the value: the match begins at the name.
  re.lastIndex = Math.max(0, finding.start - 4096);
  let covering;
  for (let m = re.exec(text); m !== null; m = re.exec(text)) {
    if (m.index > finding.end) break;
    if (m[0].length === 0) re.lastIndex++;
    if (m.index > finding.start || m.index + m[0].length < finding.end) continue;
    // The value the scanner picks: the rule's secret group, else the first
    // group that took part, else the whole match.
    const g = pattern.secretGroup && m[pattern.secretGroup] !== undefined ? pattern.secretGroup : (m.findIndex((v, i) => i > 0 && v !== undefined && v.length > 0) + 1 || 1) - 1;
    const [s, e] = m.indices[g] ?? m.indices[0];
    if (s === finding.start && e === finding.end) return m;
    covering ??= m;
  }
  return covering;
}

/**
 * `(from, to, name) => string`: the text between two offsets, masked. Every
 * span of `spans` is masked as one value, and every other letter and digit
 * with `maskAll`. `name` is `{start, end, text}`: what to write in place of
 * the record's own name (see `nameIn`). With `raw`, the text itself.
 */
function maskedView(text, spans, { raw, known, key }) {
  if (raw) return (from, to) => text.slice(from, to);
  const sorted = [...spans].sort((a, b) => a.start - b.start);
  const rest = (a, b, name) => {
    if (a >= b) return "";
    if (name === undefined || name.end <= a || name.start >= b) return maskAll(text.slice(a, b), known, key);
    const s = Math.max(a, name.start);
    const e = Math.min(b, name.end);
    return maskAll(text.slice(a, s), known, key) + name.text.slice(s - name.start, e - name.start) + maskAll(text.slice(e, b), known, key);
  };
  return (from, to, name) => {
    let out = "";
    let at = from;
    for (const s of sorted) {
      if (s.end <= at || s.start >= to) continue;
      const a = Math.max(s.start, at);
      const b = Math.min(s.end, to);
      // Mask the whole value, then keep the part inside the window: a value cut
      // by the window's edge masks the same way as the full one elsewhere.
      out += rest(at, a, name) + maskValue(text.slice(s.start, s.end), key).slice(a - s.start, b - s.start);
      at = b;
    }
    return out + rest(at, to, name);
  };
}

/**
 * The record's name as it is written, and where it stands. Raw: the name.
 * Masked: `maskName` of it, and the place of the name on the value's line (the
 * last one before the value), so that the line shows the same masked name.
 */
function nameIn(text, name, valueStart, { raw, key }) {
  if (name === undefined || name === null) return { name: null };
  if (raw) return { name };
  const masked = maskName(name, key);
  const lineStart = text.lastIndexOf("\n", valueStart - 1) + 1;
  const at = text.lastIndexOf(name, valueStart - name.length);
  return at < lineStart ? { name: masked } : { name: masked, place: { start: at, end: at + name.length, text: masked } };
}

// Every other place `text` repeats one of the values of `spans` (4 characters
// and more): a line that assigns a value often repeats it (an echo, a test's
// expectation), and only one of those is a finding.
function withRepeats(text, spans) {
  const out = [...spans];
  for (const value of new Set(spans.map((s) => text.slice(s.start, s.end)))) {
    if (value.length < 4) continue;
    for (let at = text.indexOf(value); at !== -1; at = text.indexOf(value, at + value.length)) {
      const again = { start: at, end: at + value.length };
      if (!out.some((s) => overlaps(s, again))) out.push(again);
    }
  }
  return out;
}

/**
 * The candidates of one text. `engine` is `{scan, rulePatterns}` from
 * src/engine/scanner.ts. Options: `generic` (also emit generic candidates),
 * `context` (characters kept on each side), `raw` (no masking), `maskKey`,
 * and `known`: a `valueIndex` of values found elsewhere (in other files), to
 * mask here too.
 */
export function candidatesOf(text, engine, opts = {}) {
  const context = opts.context ?? 160;
  const key = opts.maskKey ?? newMaskKey();
  const patterns = new Map(engine.rulePatterns().map((p) => [p.id, p]));
  const findings = engine.scan(text, { pragmas: false });
  // Generic candidates are always computed: even when they are not emitted,
  // their values are masked wherever they fall inside a context window.
  const generic = genericCandidates(text).filter((g) => !findings.some((f) => overlaps(f, g)));
  // A value is masked wherever it stands, not only where it is a finding.
  const found = [...findings, ...generic].map((s) => ({ start: s.start, end: s.end }));
  const spans = opts.raw ? found : withRepeats(text, found);
  const show = maskedView(text, spans, { raw: opts.raw, known: opts.known, key });
  const lineOf = (offset) => {
    let line = 1;
    for (let i = text.indexOf("\n"); i !== -1 && i < offset; i = text.indexOf("\n", i + 1)) line++;
    return line;
  };
  const record = (mode, rule, span, match, groups, found) => {
    const value = text.slice(span.start, span.end);
    const from = Math.max(0, span.start - context);
    const to = Math.min(text.length, span.end + context);
    const { name, place } = nameIn(text, found, span.start, { raw: opts.raw, key });
    return {
      mode,
      rule,
      line: lineOf(span.start),
      start: span.start,
      end: span.end,
      length: span.end - span.start,
      match: match ? { start: match[0], end: match[1] } : null,
      groups,
      name,
      entropy: Number(shannonEntropy(value).toFixed(3)),
      classes: charClasses(value),
      context: { start: from, before: show(from, span.start, place), value: show(span.start, span.end), after: show(span.end, to) },
      masked: !opts.raw,
    };
  };
  const out = findings.map((f) => {
    const m = matchBehind(text, f, patterns.get(f.ruleId));
    const groups = m ? m.indices.slice(1).map((g) => g ?? null) : [];
    return record("rule", f.ruleId, f, m ? m.indices[0] : null, groups, assignedName(text, f.start));
  });
  if (opts.generic) for (const g of generic) out.push(record("generic", g.kind, g, g.match, g.groups, g.name));
  return out.sort((a, b) => a.start - b.start);
}

// ---------------------------------------------------------------- sg-cand-1 (--candidates)

export const GENERATOR = "sg-cand-1";

// Revision 1 of the generator (its single revision): `generic-keyword` reads a
// few more forms, and `auth-scheme` is added.
export const REVISION = 1;

// generic-keyword. A name is a run of letters, digits, `_`, `.`, `$` and `-`;
// it only has to CONTAIN a keyword. Everything stands on one line. An optional
// element that is there is always taken as that element: the value never
// begins with the bracket, the quote or the scheme word that precedes it.
const NAME_CHAR = String.raw`[\w.$-]`;
const QUOTES = ['"', "'", "\x60"];
const SEPARATOR = "(?::=|=>|==|!=|:|=)";
// An authentication scheme and the spaces after it: not part of the value.
const SCHEME_WORDS = "(?:bearer|basic|token|digest|negotiate|apikey) +";
const SCHEME = `(?:${SCHEME_WORDS}|(?!${SCHEME_WORDS}))`;
const VALUE = [
  // A quoted value runs to the same quote.
  ...QUOTES.map((q) => `${q}${SCHEME}([^${q}\\r\\n]{4,256})${q}`),
  // Opened by an escaped quote (one backslash), it runs to the same quote,
  // escaped too, with no bare quote of that kind before it.
  ...QUOTES.map((q) => `\\\\${q}${SCHEME}([^${q}\\r\\n]{4,256})\\\\${q}`),
  // A bare value runs to the first whitespace, `;` or `,` (or the end of the
  // line), and cannot begin with a quote, escaped or not.
  String.raw`(?!\\?["'\x60])${SCHEME}(?!\\?["'\x60])([^\s;,]{4,256})(?![^\s;,])`,
].join("|");
export const GENERIC_KEYWORD = Object.freeze({
  id: "generic-keyword",
  keywords: KEYWORDS,
  // Judged like the engine's two rules that trust a name, for the `context` flag.
  nameTrusting: true,
  re: new RegExp(
    [
      String.raw`(?<!${NAME_CHAR})${NAME_CHAR}*?(?:${KEYWORDS.join("|")})${NAME_CHAR}*`, // 1. the name
      String.raw`(?:\\?["'\x60])?[\])]?`, // 2. its closing quote, plain or escaped, then `]` or `)`
      `[ \\t]*${SEPARATOR}[ \\t]*`, // 3. the separator
      String.raw`(?:\[|(?!\[))`, // 4. `[`
      `(?:${VALUE})`, // 5 to 7. the opening quote, the scheme word, the value
    ].join(""),
    "i",
  ),
});

// auth-scheme: the value after `Bearer` or `Basic`, wherever the header name
// is (often on another line). 16 to 512 characters of the set; a longer run is
// not a candidate.
const AUTH_VALUE_CHAR = "[A-Za-z0-9._~+/=-]";
export const AUTH_SCHEME = Object.freeze({
  id: "auth-scheme",
  keywords: ["bearer", "basic"],
  re: new RegExp(`\\b(?:bearer|basic) +(${AUTH_VALUE_CHAR}{16,512})(?!${AUTH_VALUE_CHAR})`, "i"),
});
// In the order `dedupe` sees them: on the same span, generic-keyword names the
// candidate (it has the name the value is assigned to).
const EXTRA_RULES = [GENERIC_KEYWORD, AUTH_SCHEME];
const EXTRA_IDS = new Set(EXTRA_RULES.map((r) => r.id));

// Gates that still drop a match in candidate mode: the built-in rules' own
// checks (Luhn and IIN, the URL username, no whitespace and no file path in a
// quoted password) and what is the engine's own material (its placeholders,
// the text of its rules).
const KEPT_GATES = new Set(["redacted", "post", "post-match", "rule-source", "user-value"]);
// Gates that are off, and the flag each one sets on the candidate.
const FLAG_OF_GATE = {
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

function lineStartsOf(text) {
  const starts = [0];
  for (let i = text.indexOf("\n"); i !== -1; i = text.indexOf("\n", i + 1)) starts.push(i + 1);
  return starts;
}

function lineIndexAt(starts, offset) {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= offset) lo = mid;
    else hi = mid - 1;
  }
  return lo;
}

// How many Unicode code points `text` holds between two offsets.
function codePoints(text, from, to) {
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

/**
 * The sg-cand-1 candidates of one text, as records (see the top of this file).
 * `engine` is `{scan, traceMatches, dedupeFindings}` from src/engine/scanner.ts.
 * Options: `sourcePath` (the file's path: recorded, and given to the engine
 * for its path allowlist and path-scoped rules), `raw`, `maskKey`, `known`
 * (as in `candidatesOf`), `maxLine` (characters kept of each line, 1000), and
 * `dropped`: an array that receives `{rule, gate, line, start, end, offset,
 * length}` for every match a kept gate dropped.
 */
export function candidateRecords(text, engine, opts = {}) {
  const maxLine = opts.maxLine ?? 1000;
  const key = opts.maskKey ?? newMaskKey();
  const cfg = opts.sourcePath ? { sourcePath: opts.sourcePath } : {};
  const starts = lineStartsOf(text);
  const lineEnd = (i) => {
    const end = i + 1 < starts.length ? starts[i + 1] - 1 : text.length;
    return end > starts[i] && text[end - 1] === "\r" ? end - 1 : end;
  };

  const live = [];
  const dropped = [];
  for (const m of engine.traceMatches(text, cfg, EXTRA_RULES)) {
    const gate = m.gates.find((g) => KEPT_GATES.has(g));
    if (gate === undefined) live.push(m);
    else dropped.push({ ...m, gate });
  }
  // `dedupe` over the engine's own rules, as `scan` does; then once more with
  // generic-keyword and auth-scheme ranked below every one of them: they keep
  // a value only where no engine rule names it, or where it holds 6
  // characters and more around the engine rule's value. The two rank
  // together: the wider value wins, generic-keyword on the same span.
  const own = engine.dedupeFindings(
    live.filter((m) => !EXTRA_IDS.has(m.ruleId)),
    text,
  );
  const extra = EXTRA_RULES.flatMap((rule) => live.filter((m) => m.ruleId === rule.id)).map((m) =>
    m.ruleId === GENERIC_KEYWORD.id ? { ...m, name: /^[\w.$-]+/.exec(m.match)?.[0] } : m,
  );
  const kept = engine
    .dedupeFindings([...own.map((m) => ({ ...m, rule: m.ruleId, ruleId: TOP_RANK_ID })), ...extra.map((m) => ({ ...m, rule: m.ruleId, ruleId: LOWEST_RANK_ID }))], text)
    .sort((a, b) => a.start - b.start);

  // What the default engine reports in the same text, with the same path.
  const reported = engine.scan(text, cfg);

  let spans = [];
  if (!opts.raw) {
    // Every value any rule matched is masked, kept as a candidate or not:
    // the union of their spans, then every other place that repeats one.
    for (const m of [...kept, ...live, ...dropped, ...reported].sort((a, b) => a.start - b.start)) {
      const last = spans[spans.length - 1];
      if (last !== undefined && m.start < last.end) last.end = Math.max(last.end, m.end);
      else spans.push({ start: m.start, end: m.end });
    }
    spans = withRepeats(text, spans);
  }
  const show = maskedView(text, spans, { raw: opts.raw, known: opts.known, key });
  const cut = (i) => (i < 0 || i >= starts.length ? null : show(starts[i], Math.min(lineEnd(i), starts[i] + maxLine)));
  const place = (m) => {
    const line = lineIndexAt(starts, m.start);
    const endLine = lineIndexAt(starts, Math.max(m.start, m.end - 1));
    return { line, endLine, start: m.start - starts[line], end: m.end - starts[endLine] };
  };

  if (opts.dropped) {
    for (const m of dropped) {
      const at = place(m);
      opts.dropped.push({ rule: m.ruleId, gate: m.gate, line: at.line + 1, start: at.start, end: at.end, endLine: at.endLine + 1, offset: m.start, length: m.end - m.start });
    }
  }

  return kept.map((m) => {
    const at = place(m);
    const filters = { entropy: false, placeholder: false, allowlist: false, stopword: false, context: false, pragma: false };
    for (const g of m.gates) if (FLAG_OF_GATE[g]) filters[FLAG_OF_GATE[g]] = true;
    // A long line is cut to a window of `maxLine` characters around the value.
    const lineLength = lineEnd(at.line) - starts[at.line];
    const inLine = Math.min(m.end - m.start, lineLength - at.start);
    const lineFrom = lineLength <= maxLine ? 0 : Math.max(0, Math.min(at.start - Math.floor((maxLine - Math.min(inLine, maxLine)) / 2), lineLength - maxLine));
    const from = starts[at.line] + lineFrom;
    const { name, place: namePlace } = nameIn(text, m.name ?? assignedName(text, m.start), m.start, { raw: opts.raw, key });
    return {
      generator: GENERATOR,
      revision: REVISION,
      file: opts.sourcePath ?? null,
      ext: opts.sourcePath ? extname(opts.sourcePath).toLowerCase() : "",
      rule: m.rule,
      line: at.line + 1,
      start: at.start,
      end: at.end,
      cpStart: codePoints(text, starts[at.line], m.start),
      cpEnd: codePoints(text, starts[at.endLine], m.end),
      endLine: at.endLine + 1,
      offset: m.start,
      length: m.end - m.start,
      value: show(m.start, m.end),
      name,
      lineText: show(from, Math.min(lineEnd(at.line), from + maxLine), namePlace),
      lineFrom,
      prevLine: cut(at.line - 1),
      nextLine: cut(at.endLine + 1),
      entropy: Number(m.entropy.toFixed(4)),
      filters,
      reported: reported.some((f) => overlaps(f, m)),
      masked: !opts.raw,
    };
  });
}

// ---------------------------------------------------------------- files

// The walk of scripts/model-compare.mjs's census, so counts compare.
export const DEFAULT_EXTENSIONS = new Set([".ts", ".js", ".mjs", ".cjs", ".json", ".md", ".toml", ".yml", ".yaml", ".rs"]);
const SKIP_DIRS = new Set([".git", "target", ".claude", "coverage"]);

export function* walkFiles(root, opts = {}) {
  if (statSync(root).isFile()) {
    yield root;
    return;
  }
  for (const e of readdirSync(root, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
    if (e.isSymbolicLink()) continue;
    const full = join(root, e.name);
    if (e.isDirectory()) {
      if (!SKIP_DIRS.has(e.name)) yield* walkFiles(full, opts);
    } else if (e.isFile() && (opts.allText || DEFAULT_EXTENSIONS.has(extname(e.name)))) yield full;
  }
}

/** A file's text, or undefined when it is missing, empty, too large or binary;
 *  `skipped` counts which (`{missing, empty, large, binary}`). */
export function readText(file, maxBytes = 2 * 1024 * 1024, skipped = undefined) {
  const skip = (why) => {
    if (skipped) skipped[why] = (skipped[why] ?? 0) + 1;
    return undefined;
  };
  const st = statSync(file, { throwIfNoEntry: false });
  if (st === undefined || !st.isFile()) return skip("missing");
  if (st.size === 0) return skip("empty");
  if (st.size > maxBytes) return skip("large");
  const buf = readFileSync(file);
  if (buf.subarray(0, 8192).includes(0)) return skip("binary");
  return buf.toString("utf8");
}

// ---------------------------------------------------------------- command line

async function loadEngine() {
  if (typeof nodeModule.registerHooks !== "function") throw new Error("needs Node >= 22.18 (module.registerHooks and type stripping)");
  // The sources import `./x.js`; the file on disk is `./x.ts`.
  nodeModule.registerHooks({
    resolve(spec, ctx, next) {
      try {
        return next(spec, ctx);
      } catch (err) {
        if (spec.startsWith(".") && spec.endsWith(".js")) return next(`${spec.slice(0, -3)}.ts`, ctx);
        throw err;
      }
    },
  });
  const root = resolve(fileURLToPath(import.meta.url), "../..");
  const { scan, rulePatterns, traceMatches, dedupeFindings, isGloballyAllowedPath } = await import(pathToFileURL(join(root, "src/engine/scanner.ts")).href);
  return { scan, rulePatterns, traceMatches, dedupeFindings, isGloballyAllowedPath };
}

const countLines = (text) => {
  let n = text.endsWith("\n") ? 0 : 1;
  for (let i = text.indexOf("\n"); i !== -1; i = text.indexOf("\n", i + 1)) n++;
  return n;
};

const USAGE =
  "usage: rule-candidates.mjs <dir|file>... [--files-from LIST] [--base DIR] [--out FILE] [--candidates [--dropped FILE] [--max-line N]] [--generic] [--context 0..4000] [--all-text] [--max-bytes N] [--stats FILE] [--raw]";

async function main(argv) {
  const opt = { roots: [], context: 160, maxBytes: 2 * 1024 * 1024, maxLine: 1000 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--out") opt.out = argv[++i];
    else if (a === "--generic") opt.generic = true;
    else if (a === "--candidates") opt.candidates = true;
    else if (a === "--raw") opt.raw = true;
    else if (a === "--all-text") opt.allText = true;
    else if (a === "--context") opt.context = Number(argv[++i]);
    else if (a === "--max-bytes") opt.maxBytes = Number(argv[++i]);
    else if (a === "--max-line") opt.maxLine = Number(argv[++i]);
    else if (a === "--files-from") opt.filesFrom = argv[++i];
    else if (a === "--base") opt.base = argv[++i];
    else if (a === "--dropped") opt.dropped = argv[++i];
    else if (a === "--stats") opt.stats = argv[++i];
    else if (a.startsWith("--")) {
      console.error(`rule-candidates: unknown option ${a}`);
      return 2;
    } else opt.roots.push(a);
  }
  const bad =
    (opt.roots.length === 0 && !opt.filesFrom) ||
    !Number.isInteger(opt.context) ||
    opt.context < 0 ||
    opt.context > 4000 ||
    !Number.isInteger(opt.maxLine) ||
    opt.maxLine < 1 ||
    !(opt.maxBytes > 0) ||
    (opt.candidates && opt.generic) ||
    (opt.dropped && !opt.candidates);
  if (bad) {
    console.error(USAGE);
    return 2;
  }
  if (opt.raw) console.error("rule-candidates: --raw: the output holds REAL values. Treat the file as a secret.");
  const began = performance.now();
  const engine = await loadEngine();
  const maskKey = newMaskKey();
  // Paths given on the command line are read from where the command runs;
  // --base moves that place for the inputs only, so that the paths written to
  // the records (and given to the engine) are the ones below the base.
  const here = process.cwd();
  const outputs = Object.fromEntries(["out", "dropped", "stats"].map((k) => [k, opt[k] === undefined ? undefined : resolve(here, opt[k])]));
  const listed = opt.filesFrom
    ? readFileSync(resolve(here, opt.filesFrom), "utf8")
        .split("\n")
        .filter((l) => l !== "")
    : [];
  if (opt.base) process.chdir(resolve(here, opt.base));
  const files = [...opt.roots.flatMap((root) => [...walkFiles(root, opt)]), ...listed];

  const stats = { files: files.length, read: 0, skipped: { missing: 0, empty: 0, large: 0, binary: 0 }, pathAllowlisted: 0, bytes: 0, lines: 0 };
  const read = (file, count) => {
    const text = readText(file, opt.maxBytes, count ? stats.skipped : undefined);
    if (text !== undefined && count) {
      stats.read++;
      stats.bytes += Buffer.byteLength(text);
      stats.lines += countLines(text);
      if (opt.candidates && engine.isGloballyAllowedPath(file)) stats.pathAllowlisted++;
    }
    return text;
  };
  const of = opt.candidates
    ? (file, text, o) => candidateRecords(text, engine, { ...o, sourcePath: file, maxLine: opt.maxLine })
    : (file, text, o) => candidatesOf(text, engine, { generic: opt.generic, context: opt.context, ...o }).map((c) => ({ file, ...c }));

  // A value found in one file is masked in every file: a first pass collects
  // them all (a secret is often repeated where no rule has the context to
  // flag it: a test's expectation, a note).
  let known;
  if (!opt.raw) {
    const values = [];
    for (const file of files) {
      const text = read(file, false);
      if (text === undefined) continue;
      if (opt.candidates) for (const c of candidateRecords(text, engine, { sourcePath: file, raw: true })) values.push(c.value);
      else for (const c of candidatesOf(text, engine, { generic: true, context: 0, raw: true })) values.push(c.context.value);
    }
    known = valueIndex(values);
  }

  // Records are written as they come: an export of many files does not fit in
  // one string.
  const sink = (path) => {
    if (path === undefined) return undefined;
    const fd = openSync(path, "w", 0o600);
    // The mode above only counts for a file that did not exist.
    fchmodSync(fd, 0o600);
    return { write: (line) => writeSync(fd, line), close: () => closeSync(fd) };
  };
  const out = sink(outputs.out) ?? { write: (line) => process.stdout.write(line), close: () => {} };
  const droppedOut = sink(outputs.dropped);
  let total = 0;
  let filesWithCandidates = 0;
  const byMode = {};
  const byRule = {};
  const byGate = {};
  for (const file of files) {
    const text = read(file, true);
    if (text === undefined) continue;
    const dropped = [];
    const found = of(file, text, { raw: opt.raw, maskKey, known, dropped });
    if (found.length > 0) filesWithCandidates++;
    for (const c of found) {
      total++;
      if (c.mode !== undefined) byMode[c.mode] = (byMode[c.mode] ?? 0) + 1;
      byRule[c.rule] = (byRule[c.rule] ?? 0) + 1;
      out.write(`${JSON.stringify(c)}\n`);
    }
    for (const d of dropped) {
      byGate[d.gate] = (byGate[d.gate] ?? 0) + 1;
      droppedOut?.write(`${JSON.stringify({ file, ...d })}\n`);
    }
  }
  out.close();
  droppedOut?.close();
  const summary = {
    ...(opt.candidates ? { generator: GENERATOR, revision: REVISION } : {}),
    ...stats,
    filesWithCandidates,
    candidates: total,
    byRule,
    ...(opt.candidates ? { droppedByKeptGate: byGate } : { byMode }),
    masked: !opt.raw,
    seconds: Number(((performance.now() - began) / 1000).toFixed(1)),
  };
  if (outputs.stats) writeFileSync(outputs.stats, `${JSON.stringify(summary, null, 2)}\n`);
  const skipped = Object.entries(stats.skipped)
    .filter(([, n]) => n > 0)
    .map(([k, n]) => `${n} ${k}`);
  console.error(
    `rule-candidates: ${stats.read} files${skipped.length > 0 ? ` (skipped: ${skipped.join(", ")})` : ""}, ${stats.lines} lines, ${filesWithCandidates} with candidates, ${total} candidates${opt.candidates ? ` (${GENERATOR}, revision ${REVISION})` : ` ${JSON.stringify(byMode)}`}${opt.raw ? " (RAW values)" : " (values masked)"}`,
  );
  console.error(`rule-candidates: by rule ${JSON.stringify(byRule)}`);
  if (opt.candidates) console.error(`rule-candidates: dropped by a kept gate ${JSON.stringify(byGate)}; ${stats.pathAllowlisted} files under the global path allowlist`);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  process.exitCode = await main(process.argv.slice(2));
}
