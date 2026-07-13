import { randomBytes } from "node:crypto";
import { closeSync, copyFileSync, existsSync, openSync, readFileSync, renameSync, writeSync } from "node:fs";

export class SettingsParseError extends Error {
  constructor(
    public readonly path: string,
    cause: string,
  ) {
    super(`refusing to edit ${path}: it is not valid JSON (${cause}). Fix it manually, then re-run.`);
    this.name = "SettingsParseError";
  }
}

export interface EditReport {
  path: string;
  changed: boolean;
  backupPath?: string;
}

// Key-order-insensitive comparison, so a re-run that rebuilds identical
// entries in a different property order still counts as "no change".
function stableStringify(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(stableStringify).join(",")}]`;
  if (v !== null && typeof v === "object") {
    const entries = Object.entries(v as Record<string, unknown>)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, inner]) => `${JSON.stringify(k)}:${stableStringify(inner)}`);
    return `{${entries.join(",")}}`;
  }
  return JSON.stringify(v);
}

// Idempotent, corruption-safe settings editing shared by all installers:
// parse (abort loudly on corrupt JSON — never overwrite what we can't read),
// mutate a clone, no-op when nothing changed, timestamped backup of the
// original, then an atomic tmp+rename write.
export function editJsonFile(path: string, mutate: (obj: Record<string, any>) => void): EditReport {
  let original: string | undefined;
  let obj: Record<string, any> = {};
  if (existsSync(path)) {
    original = readFileSync(path, "utf8");
    if (original.trim() !== "") {
      try {
        obj = JSON.parse(original);
      } catch (err) {
        throw new SettingsParseError(path, err instanceof Error ? err.message : "parse error");
      }
      if (obj === null || typeof obj !== "object" || Array.isArray(obj)) {
        throw new SettingsParseError(path, "top level is not an object");
      }
    }
  }

  const mutated = structuredClone(obj);
  mutate(mutated);
  const next = `${JSON.stringify(mutated, null, 2)}\n`;
  if (stableStringify(obj) === stableStringify(mutated)) {
    return { path, changed: false };
  }

  let backupPath: string | undefined;
  if (original !== undefined) {
    const stamp = new Date().toISOString().replaceAll(/[:.]/g, "-");
    backupPath = `${path}.secretgate-backup-${stamp}`;
    copyFileSync(path, backupPath);
  }
  const tmp = `${path}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
  const fd = openSync(tmp, "w", 0o644);
  try {
    writeSync(fd, next);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, path);
  return { path, changed: true, backupPath };
}
