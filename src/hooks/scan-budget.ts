import type { UserAllowlist } from "../engine/allowlist.js";
import { redactText } from "../redact.js";
import type { Vault } from "../vault/vault.js";

export const SCAN_CAP = 2 * 1024 * 1024;
const SCAN_DEADLINE_MS = 5000;

export function isBinaryField(key: string, value: unknown, parent: { type?: string }): boolean {
  return (
    (key === "data" && ["image", "audio"].includes(parent.type ?? "")) ||
    (key === "base64" && ["image", "audio"].includes(parent.type ?? "") && typeof value === "string" && /^[A-Za-z0-9+/=\s]*$/.test(value)) ||
    (key === "url" && typeof value === "string" && /^data:(image|audio)\//.test(value))
  );
}

// One budget for the entire event, including nested MCP strings.
export function eventRedactor(vault: Vault, source: string, allowlist: UserAllowlist): (text: string) => string {
  const deadline = performance.now() + SCAN_DEADLINE_MS;
  let remaining = SCAN_CAP;
  return (text) => {
    remaining -= text.length;
    const deadlineMs = deadline - performance.now();
    if (remaining < 0 || deadlineMs <= 0) throw new Error("scan budget exceeded");
    return redactText(text, vault, source, { allowlist, deadlineMs }).text;
  };
}
