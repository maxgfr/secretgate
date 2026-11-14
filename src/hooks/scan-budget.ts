import type { UserAllowlist } from "../engine/allowlist.js";
import { type Finding, scan } from "../engine/scanner.js";
import { redactText } from "../redact.js";
import type { Vault } from "../vault/vault.js";

export const SCAN_CAP = 2 * 1024 * 1024;
// Wall-clock budget per hook scan. Well under a typical agent hook timeout so a
// crafted payload can't stall the hook into a fail-open timeout; on exceed the
// scan throws and the hook fails closed.
export const SCAN_DEADLINE_MS = 5000;

/** Base64 and nothing else: what an attachment's payload looks like. */
export const isBase64Payload = (value: unknown): value is string => typeof value === "string" && /^[A-Za-z0-9+/=\s]*$/.test(value);

export function isBinaryField(key: string, value: unknown, parent: { type?: string; encoding?: unknown; mime?: unknown; media_type?: unknown }): boolean {
  return (
    (key === "data" && ["image", "audio"].includes(parent.type ?? "")) ||
    // A model content block's attachment: `{type: "image" | "document", source:
    // {type: "base64", media_type, data}}`, as PostToolBatch carries an image or a PDF.
    (key === "data" && parent.type === "base64" && typeof parent.media_type === "string" && !parent.media_type.startsWith("text/") && isBase64Payload(value)) ||
    (key === "base64" && ["image", "audio"].includes(parent.type ?? "") && isBase64Payload(value)) ||
    ((key === "url" || key === "uri") && typeof value === "string" && /^data:(image|audio)\//.test(value)) ||
    // OpenCode 2 `read` of an image: `{ content, encoding: "base64", mime: "image/png" }`.
    (key === "content" && parent.encoding === "base64" && typeof parent.mime === "string" && /^(image|audio)\//.test(parent.mime) && isBase64Payload(value))
  );
}

// One budget for the entire event, including nested MCP strings.
// No source path is handed to the engine, although a Read names its file: a
// path only ever switches scanning OFF (upstream exempts node_modules,
// lockfiles and vendor trees whole; path-scoped rules stop running elsewhere),
// and a path is what a repository or an agent arranges most easily. Those
// allowlists are for `scan`, where the repository describes its own files.
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

// The same budget for text that can only be refused, never rewritten: the
// findings of one result's strings, with nothing recorded in the vault. The
// deadline is the caller's, so several results can share one.
export function resultScanner(allowlist: UserAllowlist, deadline: number): (text: string) => Finding[] {
  let remaining = SCAN_CAP;
  return (text) => {
    remaining -= text.length;
    const deadlineMs = deadline - performance.now();
    if (remaining < 0 || deadlineMs <= 0) throw new Error("scan budget exceeded");
    return scan(text, { allowlist, deadlineMs, pragmas: false });
  };
}
