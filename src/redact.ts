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
export function redactText(text: string, vault: Vault, source: string, cfg: ScanConfig = {}): RedactResult {
  const findings = scan(text, { ...cfg, pragmas: cfg.pragmas ?? false });
  if (findings.length === 0) return { text, findings, replaced: [] };
  // One vault cycle for the whole text, then one pass to rebuild it: findings
  // come back sorted by position and never overlap.
  const ordered = [...findings].sort((a, b) => a.start - b.start);
  const placeholders = vault.recordSecrets(ordered.map((f) => ({ secret: f.secret, ruleId: f.ruleId, source })));
  const pieces: string[] = [];
  let at = 0;
  ordered.forEach((f, i) => {
    pieces.push(text.slice(at, f.start), placeholders[i]!);
    at = f.end;
  });
  pieces.push(text.slice(at));
  return { text: pieces.join(""), findings, replaced: ordered.map((f, i) => ({ placeholder: placeholders[i]!, ruleId: f.ruleId })) };
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
export function restorePlaceholders(text: string, vault: Vault): RestoreResult {
  if (!text.includes(PLACEHOLDER_PREFIX)) return { text, restored: 0 };
  const lookup = vault.lookup();
  let restored = 0;
  const out = text.replace(PLACEHOLDER_RE, (match) => {
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
  return { text: out, restored };
}
