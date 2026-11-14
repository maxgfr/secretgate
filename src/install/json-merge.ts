import { copyFileSync, existsSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { rewriteFileAtomic } from "../fs-atomic.js";
import { canonical, covers } from "../paths.js";

export class SettingsParseError extends Error {
  constructor(
    public readonly path: string,
    cause: string,
  ) {
    super(`refusing to edit ${path}: it is not valid JSON (${cause}). Fix it manually, then re-run.`);
    this.name = "SettingsParseError";
  }
}

/** Through a symlink, the file would be written outside the tree it belongs
 *  to, or into a file that is not a settings file. */
export class SettingsLinkError extends Error {
  constructor(
    public readonly path: string,
    target: string,
    why: string,
  ) {
    super(
      `refusing to edit ${path}: through a symbolic link it resolves to ${target}, ${why}. Replace the link with a regular file (or point it at a settings file inside that directory), then re-run.`,
    );
    this.name = "SettingsLinkError";
  }
}

// Directories an agent keeps its own settings in: a file inside one is a
// settings file whatever its name.
const SETTINGS_DIRS = new Set([".claude", ".codex", "opencode"]);

/**
 * A settings file may be a symlink, or sit under one: a dotfiles checkout in
 * the user's home, a shared file elsewhere in the project. Writing through it
 * is right when what it resolves to
 *   - stays inside the tree the settings belong to (`roots`: the project for
 *     project settings, the user's home for global ones), and
 *   - can be a settings file of that kind: it has the same name, or sits in a
 *     directory named like an agent's own (`.claude`, `.codex`, `opencode`).
 * Otherwise the link is not followed, and nothing is read or written: a
 * repository can commit `.claude/settings.json` as a link to any file of the
 * user — or to its own `package.json`, into which the hooks would go.
 */
export function assertWithin(path: string, roots: string[]): void {
  const real = canonical(path);
  if (!roots.some((root) => covers(root, real)))
    throw new SettingsLinkError(path, real, `outside ${roots[0] ?? dirname(path)} (secretgate only writes through a link that stays inside that directory)`);
  if (
    basename(real).toLowerCase() !== basename(path).toLowerCase() &&
    !dirname(real)
      .split(/[\\/]/)
      .some((segment) => SETTINGS_DIRS.has(segment))
  )
    throw new SettingsLinkError(path, real, `which is not a settings file (another name than ${basename(path)}, and not in a directory of the agent's own)`);
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
// original, then an atomic tmp+rename write that keeps the file's permission
// bits and writes through a symlink — one that stays inside `within` (the
// file's own directory when none is given; see assertWithin). `latestBackupOnly`
// keeps just the newest backup — for files secretgate alone writes, rewritten
// on every install.
export function editJsonFile(
  path: string,
  mutate: (obj: Record<string, any>) => void,
  opts: { latestBackupOnly?: boolean; within?: string[] } = {},
): EditReport {
  assertWithin(path, opts.within ?? [dirname(path)]);
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
  rewriteFileAtomic(path, next);
  return { path, changed: true, backupPath };
}
