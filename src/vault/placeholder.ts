import { createHmac } from "node:crypto";

// Placeholders are HMAC-derived so the same secret always maps to the same
// token across sessions (the model's references stay consistent), while the
// per-install random salt keeps the mapping non-reversible without the vault.
export function placeholderFor(secret: string, salt: string, hexLen = 12): string {
  const digest = createHmac("sha256", salt).update(secret).digest("hex");
  return `SECRETGATE_${digest.slice(0, hexLen)}`;
}

export const PLACEHOLDER_RE = /SECRETGATE_[0-9a-f]{12,16}/g;
