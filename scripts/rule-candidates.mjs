#!/usr/bin/env node
// Candidate export: one JSON line per rule finding, with what the scanner knows
// at match time. Dev-only (not in the bundle): it builds the data a later
// model needs to judge a rule candidate in its context and answer P(real
// secret). The rule side is secretgate's own scanner, imported from the
// TypeScript sources through Node's type stripping (Node >= 22.18).
//
//   node scripts/rule-candidates.mjs <dir|file>... [--out FILE] [--generic]
//     [--context 160] [--all-text] [--max-bytes 2097152] [--raw]
//
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
//   masked    whether the values in `context` are masked
//
// MASKED BY DEFAULT. Every character of every candidate value (the line's own
// and any other that falls in its context window) is replaced by another one
// of the same class: a lower-case letter by a lower-case letter, a digit by a
// digit; punctuation stays. Length and shape survive, the value does not. The
// mapping is keyed by a random key drawn for the run and never written, so the
// same value masks the same way within one export and cannot be recomputed
// afterwards. A candidate's value is masked at every place the walked files
// repeat it (values of 8 characters and more across files, any length within
// its own file), which takes a first pass over all of them. Values no rule and
// no generic pattern proposes are NOT masked: an export is as clean as the
// candidates are complete. --raw writes real values; it has to be asked for.
//
// --generic adds high-recall candidates the rules do not propose: any value
// assigned to a name that sounds like a credential (password, secret, token,
// key, auth…), whatever its entropy, quoting or stopwords, and the value of an
// Authorization-style header. Scanned like tool output: no source path, no
// pragmas. Nothing here touches the network; it writes --out (or stdout).
import { createHmac, randomBytes } from "node:crypto";
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
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

/** A fresh key for one export. */
export const newMaskKey = () => randomBytes(32);

/**
 * `value` with every letter and digit replaced by a DIFFERENT character of the
 * same class; everything else is kept (punctuation, and characters outside the
 * Basic Multilingual Plane). Deterministic for a given key.
 */
export function maskValue(value, key) {
  let stream = Buffer.alloc(0);
  let block = 0;
  let out = "";
  for (let i = 0; i < value.length; i++) {
    const c = value[i];
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
  // A value is masked wherever it stands: a line that assigns it often repeats
  // it (an echo, a test's expectation), and only one of those is a finding.
  const spans = [...findings, ...generic].map((s) => ({ start: s.start, end: s.end }));
  if (!opts.raw) {
    for (const value of new Set(spans.map((s) => text.slice(s.start, s.end)))) {
      if (value.length < 4) continue;
      for (let at = text.indexOf(value); at !== -1; at = text.indexOf(value, at + value.length)) {
        const again = { start: at, end: at + value.length };
        if (!spans.some((s) => overlaps(s, again))) spans.push(again);
      }
    }
  }
  spans.sort((a, b) => a.start - b.start);
  const show = (from, to) => {
    if (opts.raw) return text.slice(from, to);
    let out = "";
    let at = from;
    for (const s of spans) {
      if (s.end <= at || s.start >= to) continue;
      const a = Math.max(s.start, at);
      const b = Math.min(s.end, to);
      // Mask the whole value, then keep the part inside the window: a value cut
      // by the window's edge masks the same way as the full one elsewhere.
      out += maskKnown(text.slice(at, a), opts.known, key) + maskValue(text.slice(s.start, s.end), key).slice(a - s.start, b - s.start);
      at = b;
    }
    return out + maskKnown(text.slice(at, to), opts.known, key);
  };
  const lineOf = (offset) => {
    let line = 1;
    for (let i = text.indexOf("\n"); i !== -1 && i < offset; i = text.indexOf("\n", i + 1)) line++;
    return line;
  };
  const record = (mode, rule, span, match, groups, name) => {
    const value = text.slice(span.start, span.end);
    const from = Math.max(0, span.start - context);
    const to = Math.min(text.length, span.end + context);
    return {
      mode,
      rule,
      line: lineOf(span.start),
      start: span.start,
      end: span.end,
      length: span.end - span.start,
      match: match ? { start: match[0], end: match[1] } : null,
      groups,
      name: name ?? null,
      entropy: Number(shannonEntropy(value).toFixed(3)),
      classes: charClasses(value),
      context: { start: from, before: show(from, span.start), value: show(span.start, span.end), after: show(span.end, to) },
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

/** A file's text, or undefined when it is empty, too large or binary. */
export function readText(file, maxBytes = 2 * 1024 * 1024) {
  const st = statSync(file);
  if (st.size === 0 || st.size > maxBytes) return undefined;
  const buf = readFileSync(file);
  if (buf.subarray(0, 8192).includes(0)) return undefined;
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
  const { scan, rulePatterns } = await import(pathToFileURL(join(root, "src/engine/scanner.ts")).href);
  return { scan, rulePatterns };
}

async function main(argv) {
  const opt = { roots: [], context: 160, maxBytes: 2 * 1024 * 1024 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--out") opt.out = argv[++i];
    else if (a === "--generic") opt.generic = true;
    else if (a === "--raw") opt.raw = true;
    else if (a === "--all-text") opt.allText = true;
    else if (a === "--context") opt.context = Number(argv[++i]);
    else if (a === "--max-bytes") opt.maxBytes = Number(argv[++i]);
    else if (a.startsWith("--")) {
      console.error(`rule-candidates: unknown option ${a}`);
      return 2;
    } else opt.roots.push(a);
  }
  if (opt.roots.length === 0 || !Number.isInteger(opt.context) || opt.context < 0 || opt.context > 4000) {
    console.error("usage: rule-candidates.mjs <dir|file>... [--out FILE] [--generic] [--context 0..4000] [--all-text] [--max-bytes N] [--raw]");
    return 2;
  }
  if (opt.raw) console.error("rule-candidates: --raw: the output holds REAL values. Treat the file as a secret.");
  const engine = await loadEngine();
  const maskKey = newMaskKey();
  const files = opt.roots.flatMap((root) => [...walkFiles(root, opt)]);
  // A value found in one file is masked in every file: a first pass collects
  // them all (a secret is often repeated where no rule has the context to
  // flag it: a test's expectation, a note).
  let known;
  if (!opt.raw) {
    const values = [];
    for (const file of files) {
      const text = readText(file, opt.maxBytes);
      if (text !== undefined) for (const c of candidatesOf(text, engine, { generic: true, context: 0, raw: true })) values.push(c.context.value);
    }
    known = valueIndex(values);
  }
  const lines = [];
  const stats = { files: 0, filesWithCandidates: 0, byMode: {}, byRule: {} };
  for (const file of files) {
    const text = readText(file, opt.maxBytes);
    if (text === undefined) continue;
    stats.files++;
    const found = candidatesOf(text, engine, { ...opt, maskKey, known });
    if (found.length > 0) stats.filesWithCandidates++;
    for (const c of found) {
      stats.byMode[c.mode] = (stats.byMode[c.mode] ?? 0) + 1;
      stats.byRule[c.rule] = (stats.byRule[c.rule] ?? 0) + 1;
      lines.push(JSON.stringify({ file, ...c }));
    }
  }
  const body = lines.length > 0 ? `${lines.join("\n")}\n` : "";
  if (opt.out) writeFileSync(opt.out, body, { mode: 0o600 });
  else process.stdout.write(body);
  console.error(
    `rule-candidates: ${stats.files} files, ${stats.filesWithCandidates} with candidates, ${lines.length} candidates ${JSON.stringify(stats.byMode)}${opt.raw ? " (RAW values)" : " (values masked)"}`,
  );
  console.error(`rule-candidates: by rule ${JSON.stringify(stats.byRule)}`);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  process.exitCode = await main(process.argv.slice(2));
}
