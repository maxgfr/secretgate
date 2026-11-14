import type { UserAllowlist } from "../engine/allowlist.js";
import { type Finding, scan } from "../engine/scanner.js";
import { redactText } from "../redact.js";
import type { Vault } from "../vault/vault.js";

export const SCAN_CAP = 2 * 1024 * 1024;
// Wall-clock budget per hook scan. Well under a typical agent hook timeout so a
// crafted payload can't stall the hook into a fail-open timeout; on exceed the
// scan throws and the hook fails closed.
export const SCAN_DEADLINE_MS = 5000;

// A field that holds an image or a sound is not text and is left out of the
// scan — for what it HOLDS, not for what it is called. On any tool, `{type:
// "image", data: "…"}` used to be skipped unread, and `AWS <key id> <secret
// key>` passed for base64 because the pattern allowed spaces.
export function isBinaryField(key: string, value: unknown, parent: { type?: string; encoding?: unknown; mime?: unknown; mimeType?: unknown }): boolean {
  const media = ["image", "audio"].includes(parent.type ?? "");
  if ((key === "data" || key === "base64") && media) return isAttachmentPayload(value, parent.mimeType ?? parent.mime);
  if ((key === "url" || key === "uri") && typeof value === "string") {
    const m = /^data:((?:image|audio)\/[^;,]*)(?:;[^;,]*)*;base64,/.exec(value);
    return m !== null && isAttachmentPayload(value.slice(m[0].length), m[1]);
  }
  // OpenCode 2 `read` of an image: `{ content, encoding: "base64", mime: "image/png" }`.
  if (key === "content" && parent.encoding === "base64" && typeof parent.mime === "string" && /^(image|audio)\//.test(parent.mime))
    return isAttachmentPayload(value, parent.mime);
  return false;
}

const ascii = (text: string): number[] => [...text].map((c) => c.charCodeAt(0));
// The first bytes of the formats an attachment comes in: [offset, bytes].
const SIGNATURES: Array<Array<[number, number[]]>> = [
  [[0, [0x89, ...ascii("PNG\r\n"), 0x1a, 0x0a]]],
  [[0, [0xff, 0xd8, 0xff]]], // JPEG
  [[0, ascii("GIF87a")]],
  [[0, ascii("GIF89a")]],
  [
    [0, ascii("RIFF")],
    [8, ascii("WEBP")],
  ],
  [
    [0, ascii("RIFF")],
    [8, ascii("WAVE")],
  ],
  [
    [0, ascii("FORM")],
    [8, ascii("AIF")],
  ],
  [[0, [0x49, 0x49, 0x2a, 0x00]]], // TIFF
  [[0, [0x4d, 0x4d, 0x00, 0x2a]]],
  [[4, ascii("ftyp")]], // HEIC, AVIF, MP4, M4A
  [[0, [0x00, 0x00, 0x01, 0x00]]], // ICO
  [[0, ascii("8BPS")]],
  [[0, ascii("OggS")]],
  [[0, ascii("fLaC")]],
  [[0, ascii("ID3")]],
  [[0, ascii("MThd")]],
  [[0, [0x1a, 0x45, 0xdf, 0xa3]]], // WebM, Matroska
];
// Too short to prove anything alone: only with a declared type that agrees.
const SIGNATURES_BY_TYPE: Array<[RegExp, number[], number?]> = [
  [/^image\/(?:x-)?(?:ms-)?bmp$/, ascii("BM")],
  [/^image\/jxl$/, [0xff, 0x0a]],
  [/^audio\/(?:mpeg|mp3|aac|aacp)$/, [0xff, 0xe0], 0xe0], // frame sync: 11 set bits
];

function hasSignature(head: Buffer, declared: string): boolean {
  const at = (offset: number, bytes: number[]): boolean => bytes.every((b, i) => head[offset + i] === b);
  if (SIGNATURES.some((parts) => parts.every(([offset, bytes]) => at(offset, bytes)))) return true;
  for (const [type, bytes, mask] of SIGNATURES_BY_TYPE) {
    if (!type.test(declared)) continue;
    if (mask === undefined ? at(0, bytes) : head[0] === bytes[0] && ((head[1] ?? 0) & mask) === bytes[1]) return true;
  }
  // A PDF: `%PDF-` at the start, after at most the byte-order mark and the
  // blank bytes a reader skips, within the first 1024 bytes.
  let i = at(0, [0xef, 0xbb, 0xbf]) ? 3 : 0;
  while (i < 1024 && [0x00, 0x09, 0x0a, 0x0c, 0x0d, 0x20].includes(head[i] ?? -1)) i++;
  return at(i, ascii("%PDF-"));
}

/**
 * The payload of an image, a sound or a PDF handed over as an attachment:
 * unbroken base64 whose first bytes are those of such a file. The base64
 * alphabet alone proves nothing — a key is letters and digits too. The
 * declared type is not trusted to say what the bytes are (a JPEG filed as a
 * PNG is still an image); it only settles the two-byte signatures. Callers
 * decide WHERE an attachment may stand; this says whether the value is one.
 */
export function isAttachmentPayload(value: unknown, declared?: unknown): value is string {
  if (typeof value !== "string" || value.length < 8 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return false;
  return hasSignature(Buffer.from(value.slice(0, 1400), "base64"), typeof declared === "string" ? declared.toLowerCase() : "");
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
