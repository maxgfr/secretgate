import { lstatSync, readdirSync, statSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import type { ScopeConfig } from "./config.js";
import { pathMatchesGlob } from "./engine/allowlist.js";
import type { NormalizedToolCall } from "./hooks/tool-call.js";
import { CASE_INSENSITIVE_FS, canonical, covers, expandHome } from "./paths.js";
import { analyzeShell, type PathRef, secretgateInvocation } from "./shell-paths.js";
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

const isOutside = (rel: string): boolean => rel === ".." || rel.startsWith(`..${sep}`) || rel.startsWith("../") || isAbsolute(rel);

const fold = (p: string): string => (CASE_INSENSITIVE_FS ? p.toLowerCase() : p);
const toPosix = (p: string): string => p.replaceAll("\\", "/");

function absolute(path: string, cwd: string): string {
  return canonical(resolve(cwd, expandHome(path)));
}

/** Path relative to the scope root, or undefined when outside it. */
function relToRoot(scope: ScopeConfig, abs: string): string | undefined {
  const rel = relative(scope.root, abs);
  if (rel === "") return "";
  // `..foo` is a name inside the root; only `..` itself or `../…` leaves it.
  if (isOutside(rel)) {
    // relative() is case-sensitive; on case-insensitive filesystems retry folded.
    if (!CASE_INSENSITIVE_FS) return undefined;
    const folded = relative(fold(scope.root), fold(abs));
    if (folded === "" || isOutside(folded)) return folded === "" ? "" : undefined;
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
  // (`dir/**` also matches `dir` itself — the matcher handles that.)
  const g = toPosix(glob.replace(/^\.\//, ""));
  if (isAbsoluteGlob(g)) {
    const expanded = toPosix(canonicalGlobBase(expandHome(g)));
    const candidates = selfAndAncestors(toPosix(abs).replace(/^\//, "")).map((p) => `/${p}`);
    return candidates.some((c) => pathMatchesGlob(c, expanded, CASE_INSENSITIVE_FS));
  }
  if (rel === undefined) return false;
  if (rel === "") return g === "." || g === "**" || g === "";
  return selfAndAncestors(rel).some((c) => pathMatchesGlob(c, g, CASE_INSENSITIVE_FS));
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

// Scratch space: `cmd > /tmp/log; tail /tmp/log` is how agents keep long
// output out of their context. A scope fences the PROJECT; temp dirs are not
// part of it (an absolute deny glob can still exclude them).
let tempRoots: string[] | undefined;
function inTempDir(abs: string): boolean {
  tempRoots ??= [...new Set([tmpdir(), "/tmp", "/var/tmp"].map((d) => canonical(d)))];
  return tempRoots.some((t) => covers(t, abs));
}

/** Why `path` is outside `scope`, or undefined when it is inside. */
export function pathOutOfScope(scope: ScopeConfig, path: string, cwd: string): string | undefined {
  const abs = absolute(path, cwd);
  const rel = relToRoot(scope, abs);
  const denied = scope.deny?.find((g) => globMatchesPath(g, rel, abs));
  if (denied) return `'${describe(rel, abs)}' matches scope.deny '${denied}'`;
  if (!scope.allow) return undefined;
  if (scope.allow.some((g) => globMatchesPath(g, rel, abs))) return undefined;
  if (rel === undefined && scope.temp !== false && inTempDir(abs)) return undefined;
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

/** Could a deny glob match something strictly below `dir`? (static fallback) */
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
    const onPrefix = parts.length <= prefix.length && parts.every((p, i) => fold(p) === fold(prefix[i]!));
    // `src/*.secret.ts` with dir `src`: the glob still has segments left.
    const hasRest = toPosix(g.replace(/^\.\//, "")).split("/").length > parts.length;
    if (onPrefix && (parts.length < prefix.length || hasRest)) return true;
    // Below the prefix, only a wildcard remainder can still reach deeper.
    const rest = toPosix(g).split("/").slice(prefix.length);
    return parts.length > prefix.length && prefix.every((p, i) => fold(p) === fold(parts[i]!)) && rest.some((seg) => seg.includes("**"));
  });
}

const TREE_LIMIT = 20_000;

// What a recursive read of `dir` would actually touch: walk it (symlinks are
// judged by their target) and return the first out-of-scope path. Precise —
// a `**/*.snap` deny only blocks when a .snap file is really there. Past
// TREE_LIMIT entries, fall back to the static answer.
function treeViolation(scope: ScopeConfig, dir: string): string | undefined {
  let seen = 0;
  const stack = [dir];
  while (stack.length > 0) {
    const current = stack.pop()!;
    let entries: import("node:fs").Dirent[];
    try {
      entries = readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      if (++seen > TREE_LIMIT) {
        const below = denyBelow(scope, dir);
        return (
          pathOutOfScope(scope, dir, dir) ?? (below ? `'${describe(relToRoot(scope, dir), dir)}' contains paths matching scope.deny '${below}'` : undefined)
        );
      }
      const full = join(current, e.name);
      if (e.isDirectory()) {
        // A denied/out-of-scope directory: report it without descending.
        const v = pathOutOfScope(scope, full, dir);
        if (v && !leadsToAllowed(scope, canonical(full))) return v;
        stack.push(full);
      } else {
        const v = pathOutOfScope(scope, full, dir);
        if (v) return v;
      }
    }
  }
  return undefined;
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
  const abs = absolute(path, cwd);
  // The policy itself stays readable: the agent should know its fence.
  if ((kind === "read" || kind === "list") && fold(basename(abs)) === ".secretgate.json") return undefined;
  const out = pathOutOfScope(scope, path, cwd);
  if (kind === "read" || kind === "write") return out;
  if (kind === "list") {
    if (!out) return undefined;
    const rel = relToRoot(scope, abs);
    if (scope.deny?.some((g) => globMatchesPath(g, rel, abs))) return out;
    return leadsToAllowed(scope, abs) ? undefined : out;
  }
  if (!isDirectory(abs)) return out;
  const v = treeViolation(scope, abs);
  return v ? `${v}, and it is below '${describe(relToRoot(scope, abs), abs)}'` : undefined;
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

/**
 * Files that decide what secretgate and the agent's hooks do: secretgate's own
 * state, any `.secretgate.json`, the agents' hook settings (`.claude/settings*.json`,
 * Codex and OpenCode configuration, globally and in `projectRoot`). One list
 * for both guards: the tamper guard asks before the agent edits them, and an
 * active scope makes them read-only.
 */
export function isPolicyFile(abs: string, projectRoot?: string): boolean {
  const name = fold(basename(abs));
  if (name === ".secretgate.json" || name === "opencode.json" || name === "opencode.jsonc") return true;
  if (fold(basename(dirname(abs))) === ".claude" && /^settings(?:\.[\w-]+)?\.json$/.test(name)) return true;
  const home = homedir();
  const roots = [process.env.CODEX_HOME ?? join(home, ".codex"), join(process.env.XDG_CONFIG_HOME ?? join(home, ".config"), "opencode")];
  if (projectRoot) roots.push(join(projectRoot, ".codex"), join(projectRoot, ".opencode"));
  return isSecretgateState(abs) || roots.some((root) => covers(root, abs));
}

/** Policy files: read-only while a scope is active. */
export function isControlFile(scope: ScopeConfig, path: string, cwd: string): boolean {
  return isPolicyFile(absolute(path, cwd), scope.root);
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

function searchAdvice(scope: ScopeConfig, refused: string): string {
  const refusedRel = relToRoot(scope, canonical(refused));
  const targets = [...new Set((scope.allow ?? []).map((g) => staticSegments(g).join("/")).filter((p) => p.length > 0 && p !== refusedRel))];
  const usable = targets.filter((t) => isDirectory(join(scope.root, t)) && !treeViolation(scope, join(scope.root, t)));
  if (usable.length > 0)
    return ` — point it at an in-scope directory explicitly (e.g. ${usable
      .slice(0, 3)
      .map((t) => `${t}/`)
      .join(", ")})`;
  return " — narrow it to files or subdirectories that are entirely in scope";
}

function shellViolation(scope: ScopeConfig, command: string | string[], cwd: string, workdir?: string): string | undefined {
  const base = workdir ? resolve(cwd, expandHome(workdir)) : cwd;
  if (workdir) {
    const v = accessViolation(scope, base, cwd, "list");
    if (v) return `working directory ${v}`;
  }
  const analysis = analyzeShell(command, { cwd: base });
  if (analysis.commands.some((argv) => secretgateInvocation(argv) === "uninstall")) return "uninstalling secretgate is not allowed while a scope is active";
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
  const strict = scope.bash === "strict";
  let kind: AccessKind;
  if (ref.kind === "exec") {
    // Running a program is not printing it; secretgate's own CLI always runs.
    if (/^secretgate(?:-opencode)?\.mjs$/.test(basename(ref.path))) return undefined;
    if (!strict)
      return scope.deny?.some((g) => globMatchesPath(g, relToRoot(scope, absolute(ref.path, cwd)), absolute(ref.path, cwd)))
        ? pathOutOfScope(scope, ref.path, cwd)
        : undefined;
    kind = "read";
  } else if (ref.kind === "read" && isDirectory(absolute(ref.path, cwd))) {
    // A directory handed to a tool (`tsc -p .`, `biome check .`): names in
    // "paths" mode, everything below it in "strict" mode.
    kind = strict ? "search" : "list";
  } else kind = ref.kind;
  const v = accessViolation(scope, ref.path, cwd, kind);
  if (!v) return undefined;
  if (kind === "search")
    return `\`${ref.command}\` would read everything under ${ref.raw === "." ? "the working directory" : `'${ref.raw}'`}: ${v}${searchAdvice(scope, ref.path)}`;
  return v;
}

/** Glob/Grep: the directory the search effectively starts from. */
function searchRootOf(call: NormalizedToolCall, cwd: string): string {
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

function entryOutOfScope(scopes: ScopeConfig[], abs: string, cwd: string): boolean {
  const kind: AccessKind = isDirectory(abs) ? "list" : "read";
  return scopes.some((s) => accessViolation(s, abs, cwd, kind) !== undefined);
}

// The file a result line is about: the longest prefix, cut at `:` or at a
// `-N-` context marker, that exists on disk. Every cut is tried, so names with
// dashes and digits (`2024-01-15-notes.md`) and drive letters (`C:\…`) work.
function pathOfLine(line: string, cwd: string): string | undefined {
  const trimmed = line.trim().replace(/^[-*]\s+/, "");
  if (trimmed === "" || trimmed === "--" || trimmed.length > 4096) return undefined;
  const cuts = [trimmed.length];
  for (const m of trimmed.matchAll(/:|-(?=\d+-)/g)) {
    cuts.push(m.index);
    if (cuts.length > 64) break;
  }
  for (const cut of cuts.sort((a, b) => b - a)) {
    const candidate = trimmed.slice(0, cut).trim();
    if (!candidate) continue;
    const abs = resolve(cwd, expandHome(candidate));
    if (exists(abs)) return abs;
  }
  return undefined;
}

function lineOutOfScope(scopes: ScopeConfig[], line: string, cwd: string): boolean | undefined {
  const abs = pathOfLine(line, cwd);
  return abs === undefined ? undefined : entryOutOfScope(scopes, abs, cwd);
}

// A directory tree (Claude Code LS `- name/`, OpenCode list `  name/`): the
// first line is an absolute directory, children are indented under it.
function filterTree(scopes: ScopeConfig[], lines: string[], cwd: string): string[] | undefined {
  const head = lines.findIndex((l) => l.trim() !== "");
  if (head === -1) return undefined;
  const rootText = lines[head]!.trim().replace(/^[-*]\s+/, "");
  if (!isAbsolute(rootText) || !isDirectory(rootText)) return undefined;
  const kept = lines.slice(0, head + 1);
  const stack: Array<{ indent: number; path: string }> = [{ indent: lines[head]!.search(/\S/), path: rootText }];
  let dropBelow: number | undefined;
  for (const line of lines.slice(head + 1)) {
    if (line.trim() === "") {
      kept.push(line);
      continue;
    }
    const indent = line.search(/\S/);
    if (dropBelow !== undefined && indent > dropBelow) continue;
    dropBelow = undefined;
    while (stack.length > 1 && stack[stack.length - 1]!.indent >= indent) stack.pop();
    const name = line
      .trim()
      .replace(/^[-*]\s+/, "")
      .replace(/\/$/, "");
    const path = isAbsolute(name) ? name : join(stack[stack.length - 1]!.path, name);
    if (exists(path) && entryOutOfScope(scopes, path, cwd)) {
      dropBelow = indent;
      continue;
    }
    kept.push(line);
    stack.push({ indent, path });
  }
  return kept;
}

/** Drop the lines of a search result that name out-of-scope files. Indented
 *  lines (OpenCode's `  Line 12: …`) follow the header line above them. */
function filterSearchText(scopes: ScopeConfig[], text: string, cwd: string): string {
  const tree = filterTree(scopes, text.split("\n"), cwd);
  if (tree) return tree.join("\n");
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
      // An array entry is a whole path (Glob `filenames`), not a grep line.
      const whole = typeof item === "string" ? resolve(cwd, expandHome(item)) : undefined;
      const out =
        whole !== undefined && exists(whole) ? entryOutOfScope(scopes, whole, cwd) : typeof item === "string" && lineOutOfScope(scopes, item, cwd) === true;
      if (out) {
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
    // "@docs team" is prose; a directory mention is written `@docs/` or `@a/b`.
    if (!explicit && !raw.includes("/") && isDirectory(abs)) continue;
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
