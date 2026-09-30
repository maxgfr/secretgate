import { realpathSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { isAllowedPath, pathMatchesGlob, type UserAllowlist } from "./engine/allowlist.js";
import { analyzeShell, expandHome } from "./shell-paths.js";
import { defaultVaultHome } from "./vault/vault.js";

export { expandHome } from "./shell-paths.js";

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
  let head = resolve(expandHome(p));
  const tail: string[] = [];
  for (;;) {
    try {
      return join(realpathSync(head), ...[...tail].reverse());
    } catch {
      const parent = dirname(head);
      if (parent === head) return resolve(expandHome(p));
      tail.push(basename(head));
      head = parent;
    }
  }
}

function fold(p: string): string {
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
  // the project only — a home directory named `tests` exempts nothing.
  const inside = relative(canonical(cwd), real).replaceAll("\\", "/");
  if (
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
]);
const GIT_CONTENT = /^git (?:show|diff|log|blame|annotate|grep|cat-file|archive|format-patch|whatchanged|stash)$/;

// Best-effort: deny a Bash command when it READS a sensitive path — as an
// argument of a content command, or as an input redirection of ANY command
// (`tr a a < .env`). A command that merely WRITES to a sensitive path (`echo x
// > .env`, the restore-on-write target) or lists it (`ls -la .env`) is fine.
// The shared shell analyser resolves quotes, `cd`, globs (`cat .en*`), brace
// lists and `$'…'`; PostToolUse redaction is the backstop for what it misses.
export function commandTouchesSensitivePath(command: string | string[], allowlist?: UserAllowlist, cwd = process.cwd()): string | undefined {
  const analysis = analyzeShell(command, { cwd });
  for (const ref of analysis.refs) {
    if (ref.kind === "write" || ref.kind === "list" || ref.kind === "exec") continue;
    if (!ref.redirect && !CONTENT_COMMANDS.has(ref.command) && !GIT_CONTENT.test(ref.command)) continue;
    if (sensitivePathMatch(ref.path, allowlist, cwd)) return ref.raw;
  }
  return undefined;
}
