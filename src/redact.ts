import { type Finding, type ScanConfig, scan } from "./engine/scanner.js";
import { PLACEHOLDER_LENGTHS, PLACEHOLDER_PREFIX, PLACEHOLDER_RE } from "./vault/placeholder.js";
import type { Vault } from "./vault/vault.js";

export interface RedactResult {
  text: string;
  findings: Finding[];
  /** placeholder + rule for each replacement actually made */
  replaced: Array<{ placeholder: string; ruleId: string }>;
}

// Replace every finding's secret span with its vault placeholder. Spans are
// replaced right-to-left so earlier offsets stay valid. Redaction guards text
// bound for a model, so inline allow pragmas are ignored unless asked for:
// the text being redacted is exactly what could carry a forged one.
//
// The result is a fixed point: scanned again, it holds no finding. The text is
// scanned again further on (by the hook that runs before the next model
// request, by the history scan), and what is let through here must not be a
// secret there. The engine is built to settle in one pass; the extra rounds
// are the guarantee, not the mechanism — and if they ever run out with
// something left, the text is NOT clean: redactText throws, and the caller
// fails closed as it does for any text it could not scan.
const MAX_ROUNDS = 3;

export class RedactionUnsettledError extends Error {
  constructor() {
    super(`redaction did not settle in ${MAX_ROUNDS} rounds`);
    this.name = "RedactionUnsettledError";
  }
}

/**
 * More findings for the first round, from something other than the rules (the
 * experimental verifier): given the text and the rules' findings in it, spans
 * that none of those overlaps. Its time is not counted against the rules'
 * deadline, and a span that does overlap a rule finding is dropped here too:
 * the rules stay the authority.
 */
export type ExtraFindings = (text: string, findings: readonly Finding[]) => Finding[];

export function redactText(text: string, vault: Vault, source: string, cfg: ScanConfig = {}, extra?: ExtraFindings): RedactResult {
  let deadline = cfg.deadlineMs !== undefined ? performance.now() + cfg.deadlineMs : undefined;
  const scanNow = (t: string): Finding[] =>
    scan(t, { ...cfg, pragmas: cfg.pragmas ?? false, ...(deadline !== undefined ? { deadlineMs: deadline - performance.now() } : {}) });
  const ruleFindings = scanNow(text);
  let findings = ruleFindings;
  if (extra) {
    const t0 = performance.now();
    let proposed: Finding[] = [];
    try {
      proposed = extra(text, ruleFindings);
    } catch {
      // What only adds to the rules is never a reason to fail: the text goes
      // on as the rules leave it.
    }
    const added = proposed.filter((x) => x.end > x.start && !ruleFindings.some((f) => f.start < x.end && x.start < f.end));
    if (deadline !== undefined) deadline += performance.now() - t0;
    // Disjoint among themselves too: the first of two that overlap is kept.
    const disjoint: Finding[] = [];
    for (const x of [...added].sort((a, b) => a.start - b.start)) if (disjoint.every((d) => x.start >= d.end || x.end <= d.start)) disjoint.push(x);
    if (disjoint.length > 0) findings = [...ruleFindings, ...disjoint].sort((a, b) => a.start - b.start);
  }
  if (findings.length === 0) return { text, findings, replaced: [] };
  const replaced: RedactResult["replaced"] = [];
  let current = text;
  let found = findings;
  for (let round = 0; found.length > 0 && round < MAX_ROUNDS; round++) {
    // One vault cycle for the whole text, then one pass to rebuild it: findings
    // come back sorted by position and never overlap.
    const ordered = [...found].sort((a, b) => a.start - b.start);
    const placeholders = vault.recordSecrets(ordered.map((f) => ({ secret: f.secret, ruleId: f.ruleId, source })));
    const pieces: string[] = [];
    let at = 0;
    ordered.forEach((f, i) => {
      pieces.push(current.slice(at, f.start), placeholders[i]!);
      at = f.end;
      replaced.push({ placeholder: placeholders[i]!, ruleId: f.ruleId });
    });
    pieces.push(current.slice(at));
    current = pieces.join("");
    found = scanNow(current);
  }
  if (found.length > 0) throw new RedactionUnsettledError();
  return { text: current, findings, replaced };
}

export interface RestoreResult {
  text: string;
  restored: number;
}

// Substitute known placeholders back to their real values. Unknown
// SECRETGATE_ tokens are left as-is (never invent a value). A placeholder is
// 12 hex digits, or 16 after a collision, and the text after it can be hex
// too (`SECRETGATE_…cafe`): the greedy match is tried as the long form, then
// the short one, and whatever it did not consume stays in the text.
//
// A recorded value can itself hold a placeholder: text that was already
// redacted, with more secret material added around it, is redacted again as
// one value. Restoring goes on until nothing known is left (the depth is
// bounded, so a vault that loops on itself cannot hang a hook).
const MAX_NESTING = 4;

export function restorePlaceholders(text: string, vault: Vault): RestoreResult {
  if (!text.includes(PLACEHOLDER_PREFIX)) return { text, restored: 0 };
  const lookup = vault.lookup();
  let restored = 0;
  let out = text;
  for (let depth = 0; depth < MAX_NESTING; depth++) {
    const before = restored;
    out = out.replace(PLACEHOLDER_RE, (match) => {
      const hex = match.slice(PLACEHOLDER_PREFIX.length);
      for (const len of PLACEHOLDER_LENGTHS) {
        if (hex.length < len) continue;
        const secret = lookup(PLACEHOLDER_PREFIX + hex.slice(0, len));
        if (secret === undefined) continue;
        restored++;
        return secret + hex.slice(len);
      }
      return match;
    });
    if (restored === before || !out.includes(PLACEHOLDER_PREFIX)) break;
  }
  return { text: out, restored };
}
