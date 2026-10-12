import { copyFileSync, existsSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { writeFileAtomic } from "../fs-atomic.js";

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

/** A copy with every object's keys sorted by code unit: the order Codex
 *  hashes hook identities in, and a key-order-insensitive form to compare. */
export function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
        .map(([key, child]) => [key, canonicalize(child)]),
    );
  }
  return value;
}

// Key-order-insensitive comparison, so a re-run that rebuilds identical
// entries in a different property order still counts as "no change".
const stableStringify = (v: unknown): string => JSON.stringify(canonicalize(v));

// Idempotent, corruption-safe settings editing shared by all installers:
// parse (abort loudly on corrupt JSON — never overwrite what we can't read),
// mutate a clone, no-op when nothing changed, timestamped backup of the
// original, then an atomic tmp+rename write. `latestBackupOnly` keeps just the
// newest backup — for files secretgate alone writes, rewritten on every install.
export function editJsonFile(path: string, mutate: (obj: Record<string, any>) => void, opts: { latestBackupOnly?: boolean } = {}): EditReport {
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
    if (opts.latestBackupOnly) {
      const prefix = `${basename(path)}.secretgate-backup-`;
      for (const f of readdirSync(dirname(path))) if (f.startsWith(prefix)) rmSync(join(dirname(path), f), { force: true });
    }
    copyFileSync(path, backupPath);
  }
  writeFileAtomic(path, next, 0o644);
  return { path, changed: true, backupPath };
}
