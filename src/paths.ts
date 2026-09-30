import { realpathSync } from "node:fs";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
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
  for (const p of spellings) {
    // case-insensitive: on macOS/Windows `.ENV` and `.env` are the SAME file, so
    // matching case-sensitively would let `Read(".ENV")` / `cat .ENV` slip past.
    if (EXEMPT_GLOBS.some((g) => pathMatchesGlob(p, g, true))) continue;
    const hit = SENSITIVE_GLOBS.find((g) => pathMatchesGlob(p, g, true));
    if (hit) return hit;
  }
  return undefined;
}

// Best-effort: deny a Bash command when it READS a sensitive path — as an
// argument of any command that prints, copies or sources it, or as an input
// redirection. A command that merely WRITES to a sensitive path (`echo x >
// .env`, the restore-on-write target) or lists it (`ls -la .env`) is fine. The
// shared shell analyser resolves quotes, `cd`, globs (`cat .en*`) and brace
// lists; PostToolUse redaction is the backstop for what it cannot see.
export function commandTouchesSensitivePath(command: string | string[], allowlist?: UserAllowlist, cwd = process.cwd()): string | undefined {
  const analysis = analyzeShell(command, { cwd });
  for (const ref of analysis.refs) {
    if (ref.kind === "write" || ref.kind === "list") continue;
    if (sensitivePathMatch(ref.path, allowlist, cwd)) return ref.raw;
  }
  return undefined;
}
