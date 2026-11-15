import { createHash } from "node:crypto";
import { appendFileSync, mkdirSync, readFileSync, renameSync, rmSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { isDisabledRule, type UserAllowlist } from "../engine/allowlist.js";
import { shannonEntropy } from "../engine/entropy.js";
import type { Finding } from "../engine/scanner.js";
import { defaultVaultHome } from "../vault/vault.js";
import { runJobBounded } from "./child.js";
import { VERIFIER_HARD_MS, VERIFIER_RULE_ID } from "./common.js";
import type { VerifierConfig } from "./config.js";
import type { VerifierJob } from "./job.js";

export { debugFromEnv, repositoryPath, VERIFIER_RULE_ID } from "./common.js";

/** The rules' deadline for re-redacting a string the verifier adds to; past it the string keeps the rules' redaction. */
export const REDACT_AGAIN_MS = 250;

// The hook side of the experimental verifier (loaded only when it is on). The
// rules' pass over the event comes first and is complete; this takes its
// strings and their rule findings, sends them to the child process under the
// hard bound, and returns, per string, the spans to redact on top of the
// rules'. When the child does not answer in time (or fails in any way), there
// is nothing to add: the hook answers with the rules' result, exactly as with
// the option off.

export interface Seen {
  text: string;
  /** the rule findings of `text` (the first round of redactText) */
  findings: readonly Finding[];
}

export interface VerifyOptions {
  config: VerifierConfig;
  allowlist?: UserAllowlist;
  /** a trustworthy path below the repository (a Read's file), else none */
  path?: string;
  debug?: (line: string) => void;
  /** what the debug line says this was */
  label: string;
  hardMs?: number;
}

export interface Verified {
  /** per string, the verifier spans to redact (none overlaps a rule finding) */
  extra: Map<string, Finding[]>;
  /** whether the child answered (else nothing was judged) */
  completed: boolean;
  /** `performance.now()` past which nothing more the verifier causes is done in this event: REDACT_AGAIN_MS after the child answered */
  deadline: number;
  /** the strings with a span the child accepted in them (not only spread there) */
  own: Set<string>;
}

const overlaps = (a: { start: number; end: number }, b: { start: number; end: number }): boolean => a.start < b.end && b.start < a.end;
const PLACEHOLDER = /SECRETGATE_[0-9a-f]{12,16}/g;

const finding = (text: string, start: number, end: number): Finding => {
  const value = text.slice(start, end);
  let line = 0;
  for (let i = text.indexOf("\n"); i !== -1 && i < start; i = text.indexOf("\n", i + 1)) line++;
  return { ruleId: VERIFIER_RULE_ID, match: value, secret: value, start, end, entropy: shannonEntropy(value), line };
};

const isHigh = (c: number): boolean => c >= 0xd800 && c <= 0xdbff;
const isLow = (c: number): boolean => c >= 0xdc00 && c <= 0xdfff;

/** Whether [start, end) is a span the parent can apply to `text`: inside it, not
 *  splitting a surrogate pair, not inside or across an existing placeholder
 *  (one it holds whole is fine: the restore resolves a nested one). */
export function applicableSpan(text: string, start: number, end: number, placeholders: ReadonlyArray<{ start: number; end: number }>): boolean {
  if (!(Number.isInteger(start) && Number.isInteger(end) && start >= 0 && end > start && end <= text.length)) return false;
  if (isLow(text.charCodeAt(start)) && start > 0 && isHigh(text.charCodeAt(start - 1))) return false;
  if (end < text.length && isLow(text.charCodeAt(end)) && isHigh(text.charCodeAt(end - 1))) return false;
  return placeholders.every((p) => !overlaps(p, { start, end }) || (start <= p.start && end >= p.end));
}

// Where else a value the verifier accepted is redacted. A false acceptance
// (its precision was about 0.84 on the test repositories) must stay one wrong
// redaction, never spread through the text: another occurrence is redacted
// only when the value is long and unusual enough not to be a word or a
// fragment of code (12 characters or more, with a digit or both cases), and
// the occurrence is a whole token (no letter, digit or `_` on either side).
export const REPEAT_MIN_LENGTH = 12;
export function propagates(value: string): boolean {
  return value.length >= REPEAT_MIN_LENGTH && (/\d/.test(value) || (/[a-z]/.test(value) && /[A-Z]/.test(value)));
}
const WORD = /[\p{L}\p{N}_]/u;
function wholeToken(text: string, at: number, end: number): boolean {
  const before = at > 0 ? text.slice(Math.max(0, at - 2), at) : "";
  const after = text.slice(end, end + 2);
  const last = before ? [...before].at(-1)! : "";
  const next = after ? [...after][0]! : "";
  return !(last && WORD.test(last)) && !(next && WORD.test(next));
}

/** The verifier's spans for an event's strings, under the hard bound. Never throws. */
export function verifyStrings(seen: readonly Seen[], o: VerifyOptions): Verified {
  const none: Verified = { extra: new Map(), completed: false, deadline: 0, own: new Set() };
  try {
    if (!o.config.enabled || isDisabledRule(VERIFIER_RULE_ID, o.allowlist)) return none;
    // Each distinct string once, with its rule findings.
    const byText = new Map<string, readonly Finding[]>();
    for (const s of seen) if (s.text.length >= 4 && !byText.has(s.text)) byText.set(s.text, s.findings);
    if (byText.size === 0) return { extra: new Map(), completed: true, deadline: 0, own: new Set() };
    const texts = [...byText.keys()];
    const job: VerifierJob = {
      v: 1,
      texts,
      covered: texts.map((t) => byText.get(t)!.map((f): [number, number] => [f.start, f.end])),
      threshold: o.config.threshold,
      ...(o.allowlist ? { allowlist: o.allowlist } : {}),
      ...(o.path !== undefined ? { path: o.path } : {}),
    };
    const out = runJobBounded(job, o.hardMs ?? VERIFIER_HARD_MS);
    if (!out.ok) {
      o.debug?.(`${o.label}: NOTHING judged — the child ${out.why} after ${out.ms.toFixed(0)} ms; the rules' result stands as with the option off`);
      return none;
    }
    o.debug?.(`${o.label}: child answered in ${out.ms.toFixed(0)} ms; ${out.result.summary}`);
    // Everything below runs after the child answered, under one deadline for
    // the event (shared with the re-redaction of the hook, `deadline`).
    const deadline = performance.now() + REDACT_AGAIN_MS;
    const placeholdersOf = new Map<string, Array<{ start: number; end: number }>>();
    const placeholders = (text: string) => {
      let p = placeholdersOf.get(text);
      if (p === undefined) placeholdersOf.set(text, (p = [...text.matchAll(PLACEHOLDER)].map((m) => ({ start: m.index, end: m.index + m[0].length }))));
      return p;
    };
    // What the child accepted, each in its own text, where it can be applied
    // and overlaps no rule finding.
    const spans = new Map<string, Finding[]>();
    const own = new Set<string>();
    const values = new Set<string>();
    for (const a of out.result.accepted) {
      const text = texts[a.i];
      if (text === undefined || !applicableSpan(text, a.start, a.end, placeholders(text))) continue;
      const rules = byText.get(text)!;
      const f = finding(text, a.start, a.end);
      if (rules.some((r) => overlaps(r, f))) continue;
      const list = spans.get(text) ?? [];
      if (!list.some((x) => overlaps(x, f))) list.push(f);
      spans.set(text, list);
      own.add(text);
      if (propagates(f.secret)) values.add(f.secret);
    }
    // A long, unusual value accepted once is redacted where else the event
    // repeats it as a whole token (a value echoed by a log line): that place
    // may give the model no context, and the value would reach it in clear.
    let spread = 0;
    spreading: for (const text of texts) {
      const rules = byText.get(text)!;
      const list = spans.get(text) ?? [];
      for (const v of values) {
        for (let at = text.indexOf(v); at !== -1; at = text.indexOf(v, at + v.length)) {
          if (performance.now() > deadline) {
            o.debug?.(`${o.label}: the event's deadline passed while spreading accepted values; the strings left keep what they have`);
            if (list.length > 0)
              spans.set(
                text,
                list.sort((a, b) => a.start - b.start),
              );
            break spreading;
          }
          const end = at + v.length;
          if (!wholeToken(text, at, end) || !applicableSpan(text, at, end, placeholders(text))) continue;
          const f = finding(text, at, end);
          if (!rules.some((r) => overlaps(r, f)) && !list.some((x) => overlaps(x, f))) {
            list.push(f);
            spread++;
          }
        }
      }
      if (list.length > 0)
        spans.set(
          text,
          list.sort((a, b) => a.start - b.start),
        );
    }
    if (spread > 0) o.debug?.(`${o.label}: spread to ${spread} other place(s) of the same value`);
    return { extra: spans, completed: true, deadline, own };
  } catch {
    return none;
  }
}

// ---------------------------------------------------------------- what PostToolUse already judged
// PostToolBatch reads every result again, as the model will receive it. A
// result PostToolUse rewrote arrives as its rewrite: the verifier judged it
// there already. PostToolUse leaves the sha256 of each string it answered
// with in a file of the session; PostToolBatch skips those strings and
// removes the file. A miss only costs time: the strings are judged again.

// Outside the verifier's asset tree, which nothing the hooks do may write.
const handledDir = (): string => join(defaultVaultHome(), "verifier-batch");
// A session id is host input: it names a file only when it is a plain name
// (letters, digits, `_`, `-`; never `.` or `..`), and the file is checked to
// be directly in the record directory.
const sessionFile = (session: unknown): string | undefined => {
  if (typeof session !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(session)) return undefined;
  const dir = handledDir();
  const file = join(dir, session);
  return dirname(file) === dir && basename(file) === session ? file : undefined;
};
const digest = (s: string): string => createHash("sha256").update(s).digest("hex");

/** Records the strings PostToolUse answered with, after the verifier judged them. Never throws. */
export function recordHandled(session: unknown, strings: readonly string[]): void {
  const file = sessionFile(session);
  if (file === undefined || strings.length === 0) return;
  try {
    mkdirSync(handledDir(), { recursive: true, mode: 0o700 });
    // One append per call: concurrent PostToolUse hooks of a batch add lines.
    appendFileSync(file, `${[...new Set(strings.map(digest))].join("\n")}\n`, { mode: 0o600 });
  } catch {
    // A missing record only means judging again.
  }
}

/** The strings PostToolUse judged in this session since the last batch, and forgets them. Never throws. */
export function takeHandled(session: unknown): (s: string) => boolean {
  const file = sessionFile(session);
  let hashes = new Set<string>();
  if (file !== undefined) {
    try {
      const taken = `${file}.${process.pid}.taken`;
      renameSync(file, taken);
      hashes = new Set(
        readFileSync(taken, "utf8")
          .split("\n")
          .filter((l) => /^[0-9a-f]{64}$/.test(l)),
      );
      rmSync(taken, { force: true });
    } catch {
      // nothing recorded
    }
  }
  return (s) => hashes.size > 0 && hashes.has(digest(s));
}
