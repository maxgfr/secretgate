import { type Finding, type ScanConfig, scan } from "./engine/scanner.js";
import { PLACEHOLDER_RE } from "./vault/placeholder.js";
import type { Vault } from "./vault/vault.js";

export interface RedactResult {
  text: string;
  findings: Finding[];
  /** placeholder + rule for each replacement actually made */
  replaced: Array<{ placeholder: string; ruleId: string }>;
}

// Replace every finding's secret span with its vault placeholder. Spans are
// replaced right-to-left so earlier offsets stay valid.
export function redactText(text: string, vault: Vault, source: string, cfg: ScanConfig = {}): RedactResult {
  const findings = scan(text, cfg);
  if (findings.length === 0) return { text, findings, replaced: [] };
  let out = text;
  const replaced: Array<{ placeholder: string; ruleId: string }> = [];
  for (const f of [...findings].sort((a, b) => b.start - a.start)) {
    const placeholder = vault.recordSecret(f.secret, f.ruleId, source);
    out = out.slice(0, f.start) + placeholder + out.slice(f.end);
    replaced.push({ placeholder, ruleId: f.ruleId });
  }
  replaced.reverse();
  return { text: out, findings, replaced };
}

export interface RestoreResult {
  text: string;
  restored: number;
}

// Substitute known placeholders back to their real values. Unknown
// SECRETGATE_ tokens are left as-is (never invent a value).
export function restorePlaceholders(text: string, vault: Vault): RestoreResult {
  let restored = 0;
  const out = text.replace(PLACEHOLDER_RE, (placeholder) => {
    const secret = vault.secretFor(placeholder);
    if (secret === undefined) return placeholder;
    restored++;
    return secret;
  });
  return { text: out, restored };
}
