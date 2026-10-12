import { mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { applyEdits, modify, type ParseError, parse as parseJsonc, printParseErrorCode } from "jsonc-parser";
import { allowlistPath } from "../config.js";
import type { UserAllowlist } from "../engine/allowlist.js";
import { writeFileAtomic } from "../fs-atomic.js";

/** The allowlist file exists but cannot be used: nothing was written. */
export class AllowlistFileError extends Error {}

const KEYS = ["sha256", "rules", "paths"] as const;

// Additive writer for ~/.secretgate/allowlist.json (0600, atomic). The file is
// JSONC, like every config secretgate reads: it is edited in place, so the
// user's comments and layout survive. A file that cannot be parsed, or whose
// lists are not lists of strings, is refused rather than rewritten from
// scratch — that would silently drop every entry already in it.
export function writeAllow(add: UserAllowlist): UserAllowlist {
  const path = allowlistPath();
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    text = "";
  }
  if (text.trim() === "") text = "{}\n";
  const errors: ParseError[] = [];
  const current = parseJsonc(text, errors, { allowTrailingComma: true, disallowComments: false }) as unknown;
  if (errors.length > 0) {
    const line = text.slice(0, errors[0]!.offset).split("\n").length;
    throw new AllowlistFileError(`${path} is not valid JSON (${printParseErrorCode(errors[0]!.error)} at line ${line}) — fix it by hand, nothing was written`);
  }
  if (current === null || typeof current !== "object" || Array.isArray(current)) {
    throw new AllowlistFileError(`${path} must be a JSON object — fix it by hand, nothing was written`);
  }
  const existing = current as Record<string, unknown>;
  const merged: UserAllowlist = {};
  for (const key of KEYS) {
    const before = existing[key];
    if (before !== undefined && !(Array.isArray(before) && before.every((v) => typeof v === "string"))) {
      throw new AllowlistFileError(`${path}: "${key}" must be an array of strings — fix it by hand, nothing was written`);
    }
    const list = (before ?? []) as string[];
    const next = [...new Set([...list, ...(add[key] ?? [])])];
    merged[key] = next;
    if (next.length !== list.length) {
      text = applyEdits(text, modify(text, [key], next, { formattingOptions: { insertSpaces: true, tabSize: 2, eol: "\n" } }));
    }
  }
  writeFileAtomic(path, text, 0o600);
  return merged;
}
