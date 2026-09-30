import { lstatSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import type { ScopeConfig } from "./config.js";
import { pathMatchesGlob } from "./engine/allowlist.js";
import type { NormalizedToolCall } from "./hooks/tool-call.js";
import { CASE_INSENSITIVE_FS, canonical, covers, expandHome } from "./paths.js";
import { analyzeShell, type PathRef } from "./shell-paths.js";
import { defaultVaultHome } from "./vault/vault.js";

// The project scope: a `.secretgate.json` can fence the agent into some
// directories/files of a repository, so content outside them never reaches the
// model. Every path is canonicalized first (`~`, `..`, symlinks, /var vs
// /private/var), then matched against the scope's globs relative to the
// directory that declared it. `deny` wins over `allow`; with an `allow` list,
// everything else — including anything outside the project root — is out.
//
// Reads, writes, listings and searches are checked; shell commands go through
// the shared static analyser (best effort — the agent's OS sandbox is the hard
// boundary). While a scope is active the files that define the policy are
// read-only, or the agent could widen its own fence.

export type AccessKind = "read" | "write" | "list" | "search";

const fold = (p: string): string => (CASE_INSENSITIVE_FS ? p.toLowerCase() : p);
const toPosix = (p: string): string => p.replaceAll("\\", "/");

function absolute(path: string, cwd: string): string {
  return canonical(resolve(cwd, expandHome(path)));
}

/** Path relative to the scope root, or undefined when outside it. */
function relToRoot(scope: ScopeConfig, abs: string): string | undefined {
  const rel = relative(scope.root, abs);
  if (rel === "") return "";
  if (rel.startsWith("..") || isAbsolute(rel)) {
    // relative() is case-sensitive; on case-insensitive filesystems retry folded.
    if (!CASE_INSENSITIVE_FS) return undefined;
    const folded = relative(fold(scope.root), fold(abs));
    if (folded === "" || folded.startsWith("..") || isAbsolute(folded)) return folded === "" ? "" : undefined;
    return toPosix(abs.slice(abs.length - folded.length));
  }
  return toPosix(rel);
}

/** `a/b/c` → [a/b/c, a/b, a] */
function selfAndAncestors(rel: string): string[] {
  const parts = rel.split("/");
  return parts.map((_, i) => parts.slice(0, parts.length - i).join("/"));
}

const isAbsoluteGlob = (g: string): boolean => g.startsWith("/") || g.startsWith("~");

function globMatchesPath(glob: string, rel: string | undefined, abs: string): boolean {
  const g = toPosix(glob.replace(/^\.\//, ""));
  const variants = g.endsWith("/**") ? [g, g.slice(0, -3)] : [g];
  if (isAbsoluteGlob(g)) {
    const expanded = variants.map((v) => toPosix(canonicalGlobBase(expandHome(v))));
    const candidates = selfAndAncestors(toPosix(abs).replace(/^\//, "")).map((p) => `/${p}`);
    return expanded.some((v) => candidates.some((c) => pathMatchesGlob(c, v, CASE_INSENSITIVE_FS)));
  }
  if (rel === undefined) return false;
  if (rel === "") return variants.some((v) => v === "." || v === "**" || v === "");
  return variants.some((v) => selfAndAncestors(rel).some((c) => pathMatchesGlob(c, v, CASE_INSENSITIVE_FS)));
}

// Realpath the static (glob-free) prefix of an absolute glob, so `/tmp/**`
// matches `/private/tmp/x` on macOS.
function canonicalGlobBase(glob: string): string {
  const idx = glob.search(/[*?[{]/);
  if (idx === -1) return canonical(glob);
  const base = glob.slice(0, idx);
  const cut = base.lastIndexOf("/");
  if (cut <= 0) return glob;
  return `${canonical(base.slice(0, cut))}${glob.slice(cut)}`;
}

/** Leading glob-free segments of a relative glob (`src/lib/**` → [src, lib]). */
function staticSegments(glob: string): string[] {
  const out: string[] = [];
  for (const seg of toPosix(glob.replace(/^\.\//, "")).split("/")) {
    if (/[*?[{]/.test(seg) || seg === "") break;
    out.push(seg);
  }
  return out;
}

function describe(rel: string | undefined, abs: string): string {
  return rel === undefined ? abs : rel === "" ? "the project root" : rel;
}

/** Why `path` is outside `scope`, or undefined when it is inside. */
export function pathOutOfScope(scope: ScopeConfig, path: string, cwd: string): string | undefined {
  const abs = absolute(path, cwd);
  const rel = relToRoot(scope, abs);
  const denied = scope.deny?.find((g) => globMatchesPath(g, rel, abs));
  if (denied) return `'${describe(rel, abs)}' matches scope.deny '${denied}'`;
  if (!scope.allow) return undefined;
  if (scope.allow.some((g) => globMatchesPath(g, rel, abs))) return undefined;
  return rel === undefined ? `'${abs}' is outside the project root ${scope.root}` : `'${describe(rel, abs)}' is not in scope.allow`;
}

/** Could something allowed live below `dir`? (listing an ancestor is fine) */
function leadsToAllowed(scope: ScopeConfig, abs: string): boolean {
  if (!scope.allow) return true;
  const rel = relToRoot(scope, abs);
  return scope.allow.some((g) => {
    if (isAbsoluteGlob(g)) {
      const base = canonicalGlobBase(expandHome(g));
      const idx = base.search(/[*?[{]/);
      return covers(abs, idx === -1 ? base : dirname(`${base.slice(0, idx)}x`));
    }
    if (rel === undefined) return false;
    if (rel === "") return true;
    const prefix = staticSegments(g);
    const parts = rel.split("/");
    // `**/x` can match anywhere below any directory.
    if (prefix.length < parts.length && toPosix(g).slice(prefix.join("/").length).replace(/^\//, "").startsWith("**")) {
      return parts.slice(0, prefix.length).every((p, i) => fold(p) === fold(prefix[i]!));
    }
    return parts.length <= prefix.length && parts.every((p, i) => fold(p) === fold(prefix[i]!));
  });
}

/** Could a deny glob match something strictly below `dir`? */
function denyBelow(scope: ScopeConfig, abs: string): string | undefined {
  const rel = relToRoot(scope, abs);
  return scope.deny?.find((g) => {
    if (isAbsoluteGlob(g)) {
      const base = canonicalGlobBase(expandHome(g));
      const idx = base.search(/[*?[{]/);
      const staticDir = idx === -1 ? base : dirname(`${base.slice(0, idx)}x`);
      return covers(abs, staticDir) || covers(staticDir, abs);
    }
    if (rel === undefined) return false;
    const prefix = staticSegments(g);
    if (prefix.length === 0) return true; // `**/secret` can be anywhere
    const parts = rel === "" ? [] : rel.split("/");
    return parts.length < prefix.length ? parts.every((p, i) => fold(p) === fold(prefix[i]!)) : false;
  });
}

function isDirectory(abs: string): boolean {
  try {
    return statSync(abs).isDirectory();
  } catch {
    return false;
  }
}

function exists(abs: string): boolean {
  try {
    lstatSync(abs);
    return true;
  } catch {
    return false;
  }
}

/**
 * Why this access is out of scope, or undefined when allowed.
 *   read/write: the path itself must be in scope.
 *   list:       names only — in scope, or a directory leading to allowed paths.
 *   search:     recursive content — every file below must be in scope.
 */
export function accessViolation(scope: ScopeConfig, path: string, cwd: string, kind: AccessKind): string | undefined {
  const out = pathOutOfScope(scope, path, cwd);
  const abs = absolute(path, cwd);
  if (kind === "read" || kind === "write") return out;
  if (kind === "list") {
    if (!out) return undefined;
    const rel = relToRoot(scope, abs);
    if (scope.deny?.some((g) => globMatchesPath(g, rel, abs))) return out;
    return leadsToAllowed(scope, abs) ? undefined : out;
  }
  if (out) return out;
  const below = isDirectory(abs) ? denyBelow(scope, abs) : undefined;
  if (below) return `'${describe(relToRoot(scope, abs), abs)}' contains paths matching scope.deny '${below}'`;
  return undefined;
}

// ---------------------------------------------------------------- control files

// secretgate's own state: switches, allowlists, trust, the vault and the pinned
// hook bundle. Listed file by file so an unrelated file that happens to sit in
// SECRETGATE_HOME is not treated as policy.
const STATE_ENTRIES = ["config.json", "allowlist.json", "disabled.json", "sessions.json", "trusted.json", "vault.json", "salt", "bin", "stopped-sessions"];

/** Is `abs` one of secretgate's own state files (under SECRETGATE_HOME)? */
export function isSecretgateState(abs: string): boolean {
  const home = defaultVaultHome();
  return STATE_ENTRIES.some((entry) => covers(join(home, entry), abs));
}

function controlRoots(scope: ScopeConfig): string[] {
  const home = homedir();
  const codex = process.env.CODEX_HOME ?? join(home, ".codex");
  const xdg = process.env.XDG_CONFIG_HOME ?? join(home, ".config");
  return [codex, join(scope.root, ".codex"), join(xdg, "opencode"), join(scope.root, ".opencode")];
}

/** Files that define the policy: read-only while a scope is active. */
export function isControlFile(scope: ScopeConfig, path: string, cwd: string): boolean {
  const abs = absolute(path, cwd);
  const name = fold(basename(abs));
  if (name === ".secretgate.json") return true;
  const parent = fold(basename(dirname(abs)));
  if (parent === ".claude" && /^settings(?:\.[\w-]+)?\.json$/.test(name)) return true;
  if (name === "opencode.json" || name === "opencode.jsonc") return true;
  return isSecretgateState(abs) || controlRoots(scope).some((root) => covers(root, abs));
}

function controlViolation(scope: ScopeConfig, path: string, cwd: string): string | undefined {
  return isControlFile(scope, path, cwd)
    ? `'${path}' configures secretgate or the agent and is read-only while a scope is active (edit it yourself outside the agent)`
    : undefined;
}

// ---------------------------------------------------------------- tool calls

const SAFE_READERS = new Set([
  "cat",
  "head",
  "tail",
  "less",
  "more",
  "bat",
  "grep",
  "egrep",
  "fgrep",
  "rg",
  "jq",
  "wc",
  "ls",
  "stat",
  "file",
  "diff",
  "cmp",
  "nl",
  "tree",
  "fd",
]);
// git subcommands that never rewrite a working-tree file.
const GIT_READ_ONLY = /^git (?:diff|show|log|blame|annotate|status|grep|ls-files|cat-file|whatchanged|shortlog|add|commit|check-ignore)$/;

function searchAdvice(scope: ScopeConfig): string {
  const target = scope.allow?.map((g) => staticSegments(g).join("/")).find((p) => p.length > 0);
  return target ? ` — point it at an in-scope directory explicitly (e.g. ${target}/)` : "";
}

function shellViolation(scope: ScopeConfig, command: string | string[], cwd: string, workdir?: string): string | undefined {
  const base = workdir ? resolve(cwd, expandHome(workdir)) : cwd;
  if (workdir) {
    const v = accessViolation(scope, base, cwd, "list");
    if (v) return `working directory ${v}`;
  }
  const text = Array.isArray(command) ? command.join(" ") : command;
  if (/(?:^|[\s;&|(/])secretgate(?:\.mjs)?["']?\s+uninstall\b/.test(text)) return "uninstalling secretgate is not allowed while a scope is active";
  const analysis = analyzeShell(command, { cwd: base });
  if (scope.bash === "strict" && analysis.dynamic.length > 0) {
    return `scope.bash is "strict" and this command uses ${analysis.dynamic.slice(0, 3).join(", ")}, which cannot be checked statically — spell the paths out`;
  }
  if (analysis.unknownCwd) return "this command changes to a directory that cannot be resolved statically, so its relative paths cannot be checked";
  for (const ref of analysis.refs) {
    const v = refViolation(scope, ref, base);
    if (v) return v;
  }
  return undefined;
}

function refViolation(scope: ScopeConfig, ref: PathRef, cwd: string): string | undefined {
  // Policy files may be printed, never changed (`sed -i`, `mv`, `git checkout --`…).
  // Checked by name, so even a file that does not exist yet cannot be created.
  if (isControlFile(scope, ref.path, cwd) && (ref.kind === "write" || !(SAFE_READERS.has(ref.command) || GIT_READ_ONLY.test(ref.command)))) {
    return `'${ref.raw}' configures secretgate or the agent and is read-only while a scope is active (edit it yourself outside the agent)`;
  }
  // Bare words that name nothing on disk may be refs or messages, not paths.
  if (!ref.explicit) return undefined;
  const v = accessViolation(scope, ref.path, cwd, ref.kind);
  if (!v) return undefined;
  if (ref.kind === "search")
    return `\`${ref.command}\` would read everything under ${ref.raw === "." ? "the working directory" : `'${ref.raw}'`}: ${v}${searchAdvice(scope)}`;
  return v;
}

/** Glob/Grep: the directory the search effectively starts from. */
export function searchRootOf(call: NormalizedToolCall, cwd: string): string {
  const root = resolve(cwd, expandHome(call.searchRoot ?? "."));
  const pattern = call.pattern ? expandHome(call.pattern) : "";
  // A glob pattern can carry its own directory (`../other/**/*.ts`, `/etc/*`).
  const idx = pattern.search(/[*?[{]/);
  const prefix = idx === -1 ? "" : pattern.slice(0, idx);
  const cut = prefix.lastIndexOf("/");
  return cut === -1 ? root : resolve(root, prefix.slice(0, cut) || "/");
}

/**
 * Why this tool call leaves the scope, or undefined when it stays inside.
 * Glob/Grep over a partly in-scope tree are allowed: `filterSearchOutput`
 * removes the out-of-scope results afterwards.
 */
export function toolCallScopeViolation(scopes: ScopeConfig[], call: NormalizedToolCall, cwd: string): string | undefined {
  for (const scope of scopes) {
    const v = oneScope(scope, call, cwd);
    if (v) return `secretgate scope (${scope.file}): ${v}.`;
  }
  return undefined;
}

function oneScope(scope: ScopeConfig, call: NormalizedToolCall, cwd: string): string | undefined {
  switch (call.kind) {
    case "read":
      for (const p of call.paths) {
        const v = accessViolation(scope, p, cwd, isDirectory(absolute(p, cwd)) ? "list" : "read");
        if (v) return v;
      }
      return undefined;
    case "write":
    case "patch":
      for (const p of call.paths) {
        const v = controlViolation(scope, p, cwd) ?? accessViolation(scope, p, cwd, "write");
        if (v) return v;
      }
      return undefined;
    case "list":
      for (const p of call.paths.length > 0 ? call.paths : ["."]) {
        const v = accessViolation(scope, p, cwd, "list");
        if (v) return v;
      }
      return undefined;
    case "search": {
      const root = searchRootOf(call, cwd);
      return accessViolation(scope, root, cwd, "list");
    }
    case "shell":
      return call.command === undefined ? undefined : shellViolation(scope, call.command, cwd, call.workdir);
    default:
      // Unknown/MCP tools: only paths that name something on disk.
      for (const p of call.paths) {
        const abs = resolve(cwd, expandHome(p));
        if (!exists(abs)) continue;
        const v = accessViolation(scope, p, cwd, isDirectory(abs) ? "list" : "read");
        if (v) return v;
      }
      return undefined;
  }
}

// ---------------------------------------------------------------- output filter

function lineOutOfScope(scopes: ScopeConfig[], line: string, cwd: string): boolean | undefined {
  const trimmed = line.trim();
  if (trimmed === "" || trimmed === "--") return undefined;
  const candidate = /^(.+?)(?::\d+[:-]|-\d+-|:|$)/.exec(trimmed)?.[1]?.trim();
  if (!candidate || candidate.length > 4096) return undefined;
  const abs = resolve(cwd, expandHome(candidate));
  if (!exists(abs)) return undefined;
  return scopes.some((s) => pathOutOfScope(s, abs, cwd) !== undefined);
}

/** Drop the lines of a search result that name out-of-scope files. Indented
 *  lines (OpenCode's `  Line 12: …`) follow the header line above them. */
export function filterSearchText(scopes: ScopeConfig[], text: string, cwd: string): string {
  let dropping = false;
  const kept: string[] = [];
  for (const line of text.split("\n")) {
    const indented = /^\s/.test(line) && line.trim() !== "";
    if (!indented) {
      const out = lineOutOfScope(scopes, line, cwd);
      dropping = out === true;
    }
    if (!dropping) kept.push(line);
  }
  return kept.join("\n");
}

/** Remove out-of-scope entries from a Glob/Grep/list result (any shape). */
export function filterSearchOutput(scopes: ScopeConfig[], value: unknown, cwd: string): { value: unknown; changed: boolean } {
  if (scopes.length === 0) return { value, changed: false };
  if (typeof value === "string") {
    const filtered = filterSearchText(scopes, value, cwd);
    return { value: filtered, changed: filtered !== value };
  }
  if (Array.isArray(value)) {
    let changed = false;
    const next: unknown[] = [];
    for (const item of value) {
      if (typeof item === "string" && lineOutOfScope(scopes, item, cwd) === true) {
        changed = true;
        continue;
      }
      const r = filterSearchOutput(scopes, item, cwd);
      changed ||= r.changed;
      next.push(r.value);
    }
    return { value: next, changed };
  }
  if (value && typeof value === "object") {
    let changed = false;
    const next: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      const r = filterSearchOutput(scopes, v, cwd);
      changed ||= r.changed;
      next[k] = r.value;
    }
    if (changed && Array.isArray(next.filenames) && typeof next.numFiles === "number") next.numFiles = next.filenames.length;
    return { value: changed ? next : value, changed };
  }
  return { value, changed: false };
}

// ---------------------------------------------------------------- prompts

/** `@path` mentions that inline out-of-scope files into the prompt. */
export function promptScopeViolation(scopes: ScopeConfig[], prompt: string, cwd: string): string | undefined {
  if (scopes.length === 0) return undefined;
  for (const m of prompt.matchAll(/(?:^|[\s(])@("[^"]+"|[^\s,;)'"`]+)/g)) {
    const raw = m[1]!.replace(/^"|"$/g, "").replace(/[.:]+$/, "");
    const explicit = raw.startsWith("/") || raw.startsWith("~") || raw.startsWith("./") || raw.startsWith("../");
    const abs = resolve(cwd, expandHome(raw.replace(/#L?\d+(?:-\d+)?$/, "")));
    if (!explicit && !exists(abs)) continue;
    for (const scope of scopes) {
      const v = accessViolation(scope, abs, cwd, isDirectory(abs) ? "list" : "read");
      if (v) return `secretgate scope (${scope.file}): @${raw} — ${v}. Mention an in-scope file instead.`;
    }
  }
  return undefined;
}

/** For `secretgate scope`: a readable summary of one scope. */
export function describeScope(scope: ScopeConfig): string[] {
  return [
    `root   ${scope.root}${sep}`,
    `allow  ${scope.allow ? scope.allow.join(", ") : "(everything under the root)"}`,
    `deny   ${scope.deny?.length ? scope.deny.join(", ") : "(none)"}`,
    `bash   ${scope.bash}`,
  ];
}
