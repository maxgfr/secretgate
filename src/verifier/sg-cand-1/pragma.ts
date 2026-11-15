// Inline suppression markers, compatible with the ecosystem's conventions:
//   pragma: allowlist secret            (detect-secrets, ripsecrets)
//   pragma: allowlist nextline secret   (detect-secrets)
//   gitleaks:allow                      (gitleaks)
// Returns the set of 0-based line indexes on which findings are suppressed.
const SAME_LINE = /pragma:\s*allowlist\s+secret|gitleaks:allow/;
const NEXT_LINE = /pragma:\s*allowlist\s+nextline\s+secret/;

export function pragmaAllowedLines(text: string): Set<number> {
  const allowed = new Set<number>();
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (NEXT_LINE.test(line)) {
      allowed.add(i + 1);
    } else if (SAME_LINE.test(line)) {
      allowed.add(i);
    }
  }
  return allowed;
}
