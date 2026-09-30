import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import type { UserAllowlist } from "./engine/allowlist.js";
import { canonical } from "./paths.js";
import { defaultVaultHome } from "./vault/vault.js";

// Global config lives next to the vault (~/.secretgate/, overridable via
// SECRETGATE_HOME): config.json for behavior toggles, allowlist.json for the
// user allowlist. A project `.secretgate.json` is looked up from the working
// directory upwards (stopping at the repository root or the home directory),
// so running from a subdirectory sees the same project policy.
//
// A project file can only ever make things stricter or quieter for itself:
// its allowlist is merged additively (suppress more, never less) and its
// `scope` narrows what the agent may touch. It can never turn the firewall off.

export type BashScopeMode = "paths" | "strict";

export interface ScopeConfig {
  /** Directory holding the `.secretgate.json` that declared this scope (canonical). */
  root: string;
  /** Globs relative to `root` (or absolute / `~/`). Absent → everything allowed. */
  allow?: string[];
  /** Globs that are out of scope even when `allow` matches. */
  deny?: string[];
  bash: BashScopeMode;
  /** The config file itself, for messages. */
  file: string;
}

export interface SecretgateConfig {
  /** restore placeholders inside Bash commands (exfiltration risk) — default false */
  restoreBash: boolean;
  /** run the gitleaks binary as a second engine in `scan` when installed */
  hybrid: "auto" | "off";
  /** What the hooks honor: the user's allowlist + TRUSTED project allowlists. */
  allowlist: UserAllowlist;
  /** What `scan` honors: the user's allowlist + every project allowlist (a repo
   *  describing its own test fixtures to its own pre-commit scan). */
  scanAllowlist: UserAllowlist;
  /** Project files whose allowlist is ignored by the hooks until `secretgate trust`. */
  untrusted: string[];
  /** Every scope declared from cwd up to the project root — all of them apply. */
  scopes: ScopeConfig[];
  /** A project `.secretgate.json` that could not be used — tool calls fail closed. */
  error?: { file: string; message: string };
}

function readJsonFile(path: string): { ok: true; value: unknown } | { ok: false; missing: boolean; message: string } {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    return { ok: false, missing: true, message: "unreadable" };
  }
  try {
    return { ok: true, value: JSON.parse(raw) };
  } catch {
    return { ok: false, missing: false, message: "not valid JSON" };
  }
}

const isStringArray = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === "string" && x.trim().length > 0);

// Global files are the user's own: keep the valid parts and drop the rest, so
// a typo there never switches protection off (a dropped allowlist entry only
// means MORE gets redacted).
function strings(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string" && x.length > 0) : [];
}

function validateAllowlist(v: unknown, where: string): UserAllowlist {
  if (v === undefined) return {};
  if (v === null || typeof v !== "object" || Array.isArray(v)) throw new Error(`${where} must be an object`);
  const a = v as Record<string, unknown>;
  for (const key of ["sha256", "rules", "paths"] as const) {
    if (a[key] !== undefined && !isStringArray(a[key])) throw new Error(`${where}.${key} must be an array of non-empty strings`);
  }
  return { sha256: a.sha256 as string[] | undefined, rules: a.rules as string[] | undefined, paths: a.paths as string[] | undefined };
}

function validateScope(v: unknown, root: string, file: string): ScopeConfig | undefined {
  if (v === undefined) return undefined;
  if (v === null || typeof v !== "object" || Array.isArray(v)) throw new Error("scope must be an object");
  const s = v as Record<string, unknown>;
  for (const key of Object.keys(s)) if (!["allow", "deny", "bash"].includes(key)) throw new Error(`scope.${key} is not a known key (allow, deny, bash)`);
  if (s.allow !== undefined && !isStringArray(s.allow)) throw new Error("scope.allow must be an array of non-empty glob strings");
  if (s.deny !== undefined && !isStringArray(s.deny)) throw new Error("scope.deny must be an array of non-empty glob strings");
  if (s.bash !== undefined && s.bash !== "paths" && s.bash !== "strict") throw new Error('scope.bash must be "paths" or "strict"');
  if (s.allow === undefined && s.deny === undefined) throw new Error("scope needs an allow or a deny list");
  return {
    root,
    allow: s.allow as string[] | undefined,
    deny: s.deny as string[] | undefined,
    bash: (s.bash as BashScopeMode | undefined) ?? "paths",
    file,
  };
}

/** Project config files from `cwd` upwards, nearest first. Stops after the
 *  repository root (a `.git` entry) and never reads the home directory's own. */
export function projectConfigFiles(cwd: string): string[] {
  const files: string[] = [];
  const home = resolve(homedir());
  let dir = resolve(cwd);
  for (;;) {
    if (dir === home) break;
    const file = join(dir, ".secretgate.json");
    if (existsSync(file)) files.push(file);
    if (existsSync(join(dir, ".git"))) break;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return files;
}

export function loadConfig(cwd?: string): SecretgateConfig {
  const home = defaultVaultHome();
  const baseRead = readJsonFile(join(home, "config.json"));
  const base = (baseRead.ok && baseRead.value && typeof baseRead.value === "object" ? baseRead.value : {}) as Record<string, unknown>;
  const allowRead = readJsonFile(join(home, "allowlist.json"));
  const allow = (allowRead.ok && allowRead.value && typeof allowRead.value === "object" ? allowRead.value : {}) as Record<string, unknown>;

  const merged: Required<UserAllowlist> = { sha256: strings(allow.sha256), rules: strings(allow.rules), paths: strings(allow.paths) };
  const forScan: Required<UserAllowlist> = { sha256: [...merged.sha256], rules: [...merged.rules], paths: [...merged.paths] };
  const scopes: ScopeConfig[] = [];
  const untrusted: string[] = [];
  let error: SecretgateConfig["error"];
  const trust = cwd ? readTrust() : {};

  for (const file of cwd ? projectConfigFiles(cwd) : []) {
    const read = readJsonFile(file);
    try {
      if (!read.ok) throw new Error(read.message);
      if (read.value === null || typeof read.value !== "object" || Array.isArray(read.value)) throw new Error("must be a JSON object");
      const project = read.value as Record<string, unknown>;
      const list = validateAllowlist(project.allowlist, "allowlist");
      const scope = validateScope(project.scope, canonical(dirname(file)), file);
      const entries = (list.sha256?.length ?? 0) + (list.rules?.length ?? 0) + (list.paths?.length ?? 0);
      // A cloned repository must not be able to switch detection off for
      // itself: its allowlist reaches the hooks only once the user trusted
      // this exact content. Scopes need no trust — they only restrict.
      const targets = trust[canonical(file)] === fileHash(file) ? [merged, forScan] : [forScan];
      if (entries > 0 && targets.length === 1) untrusted.push(file);
      for (const t of targets) {
        t.sha256.push(...(list.sha256 ?? []));
        t.rules.push(...(list.rules ?? []));
        t.paths.push(...(list.paths ?? []));
      }
      if (scope) scopes.push(scope);
    } catch (err) {
      error ??= { file, message: err instanceof Error ? err.message : String(err) };
    }
  }

  return {
    restoreBash: base.restoreBash === true,
    hybrid: base.hybrid === "off" ? "off" : "auto",
    allowlist: merged,
    scanAllowlist: forScan,
    untrusted,
    scopes,
    ...(error ? { error } : {}),
  };
}

// ---------------------------------------------------------------- trust

function trustPath(): string {
  return join(defaultVaultHome(), "trusted.json");
}

export function fileHash(file: string): string | undefined {
  try {
    return createHash("sha256").update(readFileSync(file)).digest("hex");
  } catch {
    return undefined;
  }
}

function readTrust(): Record<string, string> {
  const read = readJsonFile(trustPath());
  if (!read.ok || !read.value || typeof read.value !== "object") return {};
  const files = (read.value as { files?: unknown }).files;
  return files && typeof files === "object" && !Array.isArray(files) ? (files as Record<string, string>) : {};
}

/** Trust (or, with `revoke`, forget) the current content of project files. */
export function setTrust(files: string[], revoke = false): void {
  const trust = readTrust();
  for (const file of files) {
    const key = canonical(file);
    const hash = fileHash(file);
    if (revoke || !hash) delete trust[key];
    else trust[key] = hash;
  }
  mkdirSync(defaultVaultHome(), { recursive: true, mode: 0o700 });
  const tmp = `${trustPath()}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify({ version: 1, files: trust }, null, 2), { mode: 0o600 });
  renameSync(tmp, trustPath());
}

export function allowlistPath(): string {
  return join(defaultVaultHome(), "allowlist.json");
}
