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

/** The verifier's spans for an event's strings, under the hard bound. Never throws. */
export function verifyStrings(seen: readonly Seen[], o: VerifyOptions): Verified {
  const none: Verified = { extra: new Map(), completed: false, deadline: 0 };
  try {
    if (!o.config.enabled || isDisabledRule(VERIFIER_RULE_ID, o.allowlist)) return none;
    // Each distinct string once, with its rule findings.
    const byText = new Map<string, readonly Finding[]>();
    for (const s of seen) if (s.text.length >= 4 && !byText.has(s.text)) byText.set(s.text, s.findings);
    if (byText.size === 0) return { extra: new Map(), completed: true, deadline: 0 };
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
    // What the verifier causes after the child answered (the hook redacting
    // again the strings it adds to) runs under one deadline for the event.
    const deadline = performance.now() + REDACT_AGAIN_MS;
    const placeholdersOf = new Map<string, Array<{ start: number; end: number }>>();
    const placeholders = (text: string) => {
      let p = placeholdersOf.get(text);
      if (p === undefined) placeholdersOf.set(text, (p = [...text.matchAll(PLACEHOLDER)].map((m) => ({ start: m.index, end: m.index + m[0].length }))));
      return p;
    };
    // What the child accepted, each in its own text, where it can be applied
    // and overlaps no rule finding. Only those spans: a value accepted once is
    // never looked for elsewhere in the event (a false acceptance stays one
    // wrong redaction, and a longer token or a key that holds it is untouched).
    const spans = new Map<string, Finding[]>();
    for (const a of out.result.accepted) {
      const text = texts[a.i];
      if (text === undefined || !applicableSpan(text, a.start, a.end, placeholders(text))) continue;
      const rules = byText.get(text)!;
      const f = finding(text, a.start, a.end);
      if (rules.some((r) => overlaps(r, f))) continue;
      const list = spans.get(text) ?? [];
      if (!list.some((x) => overlaps(x, f))) list.push(f);
      spans.set(text, list);
    }
    for (const list of spans.values()) list.sort((a, b) => a.start - b.start);
    return { extra: spans, completed: true, deadline };
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
