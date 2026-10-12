import { type Dirent, lstatSync, readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { isAllowedPath, pathMatchesGlob, type UserAllowlist } from "./engine/allowlist.js";
import { analyzeShell, isGitContentCommand, type ShellAnalysis, type WalkSpec } from "./shell-paths.js";
import { defaultVaultHome } from "./vault/vault.js";

export function expandHome(p: string): string {
  if (p === "~") return homedir();
  if (p.startsWith("~/")) return join(homedir(), p.slice(2));
  return p;
}

/** Does anything (a file, a directory, a dangling symlink) exist at `p`? */
export function exists(p: string): boolean {
  try {
    lstatSync(p);
    return true;
  } catch {
    return false;
  }
}

export function isDirectory(p: string): boolean {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
}

/** The directory a glob's static (wildcard-free) prefix names: `src/*.ts` → `src`. */
export function globStaticDir(glob: string): string {
  const idx = glob.search(/[*?[{]/);
  return idx === -1 ? glob : dirname(`${glob.slice(0, idx)}x`);
}

// Files whose CONTENT is assumed sensitive: the firewall denies reading them
// outright (first line of defense — the secret never even enters a tool
// result). Users widen/narrow via `secretgate allow --path` and their agent's
// own permission config.
export const SENSITIVE_GLOBS = [
  "**/.env",
  "**/.env.*",
  "**/*.pem",
  "**/*.key",
  "**/id_rsa*",
  "**/id_ed25519*",
  "**/id_ecdsa*",
  "**/.aws/**",
  "**/.ssh/**",
  "**/.kube/config",
  "**/.npmrc",
  "**/.netrc",
  "**/.docker/config.json",
  "**/credentials.json",
  "**/.envrc",
  "**/.dev.vars",
  "**/.git-credentials",
  "**/.pgpass",
  "**/.pypirc",
  "**/*.p12",
  "**/*.pfx",
  "**/*.tfstate",
  "**/*.tfstate.backup",
];

// Directories that hold fake credentials by design (see sensitivePathMatch).
export const FIXTURE_DIRS = new Set([
  "test",
  "tests",
  "__tests__",
  "spec",
  "specs",
  "fixture",
  "fixtures",
  "__fixtures__",
  "testdata",
  "test-data",
  "test_data",
  "mocks",
  "__mocks__",
  "examples",
  "samples",
]);

// Template/sample files exist to be read — never sensitive.
export const EXEMPT_GLOBS = ["**/.env.example", "**/.env.sample", "**/.env.template", "**/.env.dist", "**/.env.defaults", "**/*.pub"];

/** macOS and Windows filesystems are case-insensitive by default. */
export const CASE_INSENSITIVE_FS = process.platform === "darwin" || process.platform === "win32";

// macOS symlinks /tmp and /var under /private, and homes are symlinked on plenty
// of setups, so resolve() alone makes ONE path look like two — and a symlink
// named `notes.txt` can point at `.env`. Canonicalize the deepest ancestor that
// exists and re-append the rest, so paths that do not exist yet (a file about
// to be written, a directory created later) still compare correctly.
export function canonical(p: string): string {
  const abs = resolve(expandHome(p));
  const memo = pathMemo?.get(abs);
  if (memo !== undefined) return memo;
  let head = abs;
  const tail: string[] = [];
  let out: string;
  for (;;) {
    try {
      out = join(realpathSync(head), ...[...tail].reverse());
      break;
    } catch {
      const parent = dirname(head);
      if (parent === head) {
        out = abs;
        break;
      }
      tail.push(basename(head));
      head = parent;
    }
  }
  pathMemo?.set(abs, out);
  return out;
}

// One hook invocation asks for the same few canonical paths over and over (the
// scope root, the policy roots, every ref of a command). They cannot change
// meaningfully within one decision, so they are remembered for its duration —
// and only for it: the OpenCode plugin is a long-lived process.
let pathMemo: Map<string, string> | undefined;

export function withPathCache<T>(fn: () => T): T {
  if (pathMemo) return fn();
  pathMemo = new Map();
  try {
    return fn();
  } finally {
    pathMemo = undefined;
  }
}

export function fold(p: string): string {
  return CASE_INSENSITIVE_FS ? p.toLowerCase() : p;
}

/** `dir` covers `p` when it IS p or an ancestor of it. The `sep` guard keeps a
 *  sibling like `/proj-old` from matching `/proj`. Case-insensitive where the
 *  filesystem is. */
export function covers(dir: string, p: string): boolean {
  const a = fold(canonical(dir));
  const b = fold(canonical(p));
  return a === b || b.startsWith(a.endsWith(sep) ? a : a + sep);
}

// Globs above are rooted with `**/` so they match absolute and relative paths
// alike. Every spelling of the path is checked: as written, lexically resolved
// (`x/../.env`) and canonical (a symlink whose target is `.env`).
export function sensitivePathMatch(path: string, allowlist?: UserAllowlist, cwd = process.cwd()): string | undefined {
  const normalized = expandHome(path.replaceAll("\\", "/"));
  const absolute = resolve(cwd, normalized).replaceAll("\\", "/");
  const real = canonical(absolute).replaceAll("\\", "/");
  const spellings = [...new Set([normalized, absolute, real])];
  // The allowlist sees resolved spellings only: `tests/../.env` must not pass
  // as `tests/**`.
  const resolvedForms = [absolute, real, relative(cwd, absolute).replaceAll("\\", "/"), relative(canonical(cwd), real).replaceAll("\\", "/")];
  if (resolvedForms.some((p) => !p.split("/").includes("..") && isAllowedPath(p, allowlist))) return undefined;
  // The vault maps every placeholder back to its secret, in clear.
  const vaultHome = defaultVaultHome();
  if (covers(join(vaultHome, "vault.json"), real) || covers(join(vaultHome, "salt"), real)) return "secretgate vault";
  // Test fixtures (`tests/fixtures/server.key`, `testdata/.env`) are fake by
  // design and are exactly what a security fix has to read. They are not
  // denied; their content still goes through output redaction, so a real
  // secret committed there is masked all the same. Judged on the path INSIDE
  // the project only — a home directory named `tests` exempts nothing — and
  // only for a file that is there: a name the shell may still resolve
  // elsewhere is no fixture.
  const inside = relative(canonical(cwd), real).replaceAll("\\", "/");
  if (
    exists(real) &&
    !inside.startsWith("../") &&
    inside !== ".." &&
    !isAbsolute(inside) &&
    inside
      .split("/")
      .slice(0, -1)
      .some((seg) => FIXTURE_DIRS.has(seg.toLowerCase()))
  )
    return undefined;
  for (const p of spellings) {
    // case-insensitive: on macOS/Windows `.ENV` and `.env` are the SAME file, so
    // matching case-sensitively would let `Read(".ENV")` / `cat .ENV` slip past.
    if (EXEMPT_GLOBS.some((g) => pathMatchesGlob(p, g, true))) continue;
    const hit = SENSITIVE_GLOBS.find((g) => pathMatchesGlob(p, g, true));
    if (hit) return hit;
  }
  return undefined;
}

// Commands that print, copy, archive, upload or source a file's CONTENT. A
// command that only uses the file (`node --env-file=.env`, `docker compose
// --env-file .env`, `mv .env .env.bak`, `ssh-keygen -f key`) does not put it
// in front of the model and is not denied.
const CONTENT_COMMANDS = new Set([
  "cat",
  "head",
  "tail",
  "less",
  "more",
  "bat",
  "batcat",
  "xxd",
  "od",
  "strings",
  "hexdump",
  "nl",
  "tac",
  "base64",
  "base32",
  "sed",
  "awk",
  "gawk",
  "grep",
  "egrep",
  "fgrep",
  "rg",
  "ag",
  "ack",
  "printf",
  "print",
  "sort",
  "uniq",
  "cut",
  "tr",
  "jq",
  "yq",
  "diff",
  "cmp",
  "comm",
  "paste",
  "fold",
  "fmt",
  "column",
  "rev",
  "expand",
  "unexpand",
  "iconv",
  "split",
  "look",
  "cp",
  "install",
  "dd",
  "rsync",
  "scp",
  "tar",
  "zip",
  "gzip",
  "bzip2",
  "xz",
  "zstd",
  "source",
  ".",
  "curl",
  "wget",
  "http",
  "https",
  "xh",
  "nc",
  "ncat",
  "openssl",
  "gpg",
  "vim",
  "vi",
  "nano",
  "emacs",
  // Interpreters run their program and hand it the other files to read
  // (`perl -pe1 .env`, `python3 tool.py .env`); `xargs -a FILE` reads FILE.
  "perl",
  "ruby",
  "node",
  "nodejs",
  "deno",
  "bun",
  "php",
  "lua",
  "xargs",
]);
const PYTHON = /^python[0-9.]*$/;
const INTERPRETER_CONTENT = /^(?:perl|ruby|node|nodejs|deno|bun|php|lua|python[0-9.]*)$/;
// Commands that make a second name for a file. Under a name that is not
// itself sensitive, the content becomes readable by any later command.
const ALIASING = new Set(["ln", "mv"]);

function isContentCommand(command: string): boolean {
  return CONTENT_COMMANDS.has(command) || PYTHON.test(command) || isGitContentCommand(command);
}

export interface SensitiveShellRead {
  /** the word as written */
  raw: string;
  /** a recursive read whose tree is too large to check */
  tooMany?: boolean;
  /** the sensitive file found below a recursive read's directory */
  below?: string;
}

/**
 * The first sensitive read in an analysed command, or undefined. A path counts
 * when a content command reads it, when it is an input redirection of ANY
 * command (`tr a a < .env`), when it is renamed or linked to a name that is not
 * itself sensitive, or when a recursive reader (`grep -r`, `rg`, `tar c`,
 * `find -exec cat`) would reach it — that last one by walking the tree, bounded.
 */
export function sensitiveShellRead(analysis: ShellAnalysis, allowlist: UserAllowlist | undefined, cwd: string): SensitiveShellRead | undefined {
  for (const ref of analysis.refs) {
    if (ref.kind === "write" || ref.kind === "list" || ref.kind === "exec") continue;
    // `node --env-file=.env app.js` loads the file, it does not print it.
    if (ref.fromOption && INTERPRETER_CONTENT.test(ref.command)) continue;
    if (ALIASING.has(ref.command)) {
      if (ref.aliasTo !== undefined && sensitivePathMatch(ref.aliasTo, allowlist, cwd)) continue;
    } else if (!ref.redirect && !ref.walk && !isContentCommand(ref.command)) continue;
    if (sensitivePathMatch(ref.path, allowlist, cwd)) return { raw: ref.raw };
    if (ref.walk && isDirectory(ref.path)) {
      const below = sensitiveFileBelow(ref.path, ref.walk, allowlist, cwd);
      if (below === "overflow") return { raw: ref.raw, tooMany: true };
      if (below) return { raw: ref.raw, below };
    }
  }
  return undefined;
}

// Best-effort: deny a Bash command when it READS a sensitive path (see
// sensitiveShellRead). A command that merely WRITES to a sensitive path (`echo
// x > .env`, the restore-on-write target) or lists it (`ls -la .env`) is fine.
// The shared shell analyser resolves quotes, `cd`, globs (`cat .en*`), brace
// lists and `$'…'`; PostToolUse redaction is the backstop for what it misses.
export function commandTouchesSensitivePath(command: string | string[], allowlist?: UserAllowlist, cwd = process.cwd()): string | undefined {
  return sensitiveShellRead(analyzeShell(command, { cwd }), allowlist, cwd)?.raw;
}

// ---------------------------------------------------------------- bounded walks

/** Entries a recursive check visits before giving up on the precise answer. */
export const TREE_LIMIT = 20_000;

/**
 * Depth-first walk below `root` (symlinks are reported, never followed).
 * `visit` returns "skip" to stay out of a directory, "stop" to end the walk.
 */
export function walkTree(
  root: string,
  visit: (abs: string, entry: Dirent) => "skip" | "stop" | undefined,
  limit = TREE_LIMIT,
): "complete" | "stopped" | "overflow" {
  let seen = 0;
  const stack = [root];
  while (stack.length > 0) {
    const current = stack.pop()!;
    let entries: Dirent[];
    try {
      entries = readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      if (++seen > limit) return "overflow";
      const abs = join(current, e.name);
      const v = visit(abs, e);
      if (v === "stop") return "stopped";
      if (v !== "skip" && e.isDirectory()) stack.push(abs);
    }
  }
  return "complete";
}

interface IgnoreRule {
  base: string;
  glob: string;
  negate: boolean;
  dirOnly: boolean;
}

// The subset of .gitignore that decides what `rg`/`ag` skip by default:
// comments, negation, directory-only and anchored patterns. Good enough to
// keep `node_modules/` or `dist/` out of the walk; a pattern it gets wrong
// only makes the check stricter or looser by that one entry.
function ignoreRules(dir: string): IgnoreRule[] {
  let text: string;
  try {
    text = readFileSync(join(dir, ".gitignore"), "utf8");
  } catch {
    return [];
  }
  const rules: IgnoreRule[] = [];
  for (const raw of text.split(/\r?\n/)) {
    let line = raw.replace(/(?<!\\)\s+$/, "");
    if (line === "" || line.startsWith("#")) continue;
    const negate = line.startsWith("!");
    if (negate) line = line.slice(1);
    const dirOnly = line.endsWith("/");
    if (dirOnly) line = line.slice(0, -1);
    const anchored = line.includes("/");
    line = line.replace(/^\//, "");
    if (line === "") continue;
    rules.push({ base: dir, glob: anchored ? line : `**/${line}`, negate, dirOnly });
  }
  return rules;
}

function ignoredBy(rules: IgnoreRule[], abs: string, isDir: boolean): boolean {
  let ignored = false;
  for (const r of rules) {
    if (r.dirOnly && !isDir) continue;
    if (pathMatchesGlob(relative(r.base, abs).replaceAll("\\", "/"), r.glob)) ignored = !r.negate;
  }
  return ignored;
}

/** The repository root above `dir` (a `.git` entry), or undefined. */
export function repositoryRoot(dir: string): string | undefined {
  for (let d = resolve(dir); ; d = dirname(d)) {
    if (exists(join(d, ".git"))) return d;
    if (dirname(d) === d) return undefined;
  }
}

/** A sensitive file a recursive reader of `dir` would reach, "overflow" past
 *  TREE_LIMIT entries, or undefined. */
export function sensitiveFileBelow(dir: string, spec: WalkSpec, allowlist: UserAllowlist | undefined, cwd: string): string | "overflow" | undefined {
  const rules = new Map<string, IgnoreRule[]>();
  if (spec.ignore) {
    const top = repositoryRoot(dir) ?? dir;
    const chain: IgnoreRule[] = [];
    for (let d = resolve(dir); ; d = dirname(d)) {
      chain.unshift(...ignoreRules(d));
      if (d === top || dirname(d) === d) break;
    }
    rules.set(canonical(dir), chain);
  }
  let hit: string | undefined;
  const result = walkTree(canonical(dir), (abs, e) => {
    if (e.name === ".git") return "skip";
    if (!spec.hidden && e.name.startsWith(".")) return "skip";
    const parentRules = rules.get(dirname(abs));
    if (spec.ignore && parentRules && ignoredBy(parentRules, abs, e.isDirectory())) return "skip";
    if (e.isDirectory()) {
      if (spec.excludeDir.some((g) => pathMatchesGlob(e.name, g))) return "skip";
      if (spec.ignore) rules.set(abs, [...(parentRules ?? []), ...ignoreRules(abs)]);
      return undefined;
    }
    if (spec.include.length > 0 && !spec.include.some((g) => pathMatchesGlob(e.name, g))) return undefined;
    if (spec.exclude.some((g) => pathMatchesGlob(e.name, g))) return undefined;
    // The full check (realpath, allowlist, fixtures) only for a name that
    // could be sensitive, or a link that could lead to one.
    if (!e.isSymbolicLink() && !SENSITIVE_GLOBS.some((g) => pathMatchesGlob(abs, g, true))) return undefined;
    if (sensitivePathMatch(abs, allowlist, cwd)) {
      hit = abs;
      return "stop";
    }
    return undefined;
  });
  return result === "overflow" ? "overflow" : hit;
}
