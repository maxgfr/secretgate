import { chmodSync, copyFileSync, existsSync, mkdirSync, realpathSync, renameSync, rmSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { defaultVaultHome } from "./vault/vault.js";

// How this CLI is running, and so how it must invoke itself (hooks, self-tests):
//   binary — a `bun build --compile` executable (Homebrew). Its modules live in
//            Bun's in-memory filesystem (/$bunfs/root/…) and process.execPath IS
//            the program; no Node needed.
//   bundle — scripts/secretgate.mjs run by Node (the skill install).
//   dev    — the TypeScript sources (tests, a checkout).
export type SelfForm = "binary" | "bundle" | "dev";

export interface SelfContext {
  /** this module's file path (fileURLToPath(import.meta.url)) */
  modulePath: string;
  /** process.execPath — the compiled binary itself in binary form */
  execPath: string;
  /** the secretgate home (~/.secretgate or $SECRETGATE_HOME) */
  home: string;
}

export interface Invocation {
  file: string;
  args: string[];
}

export function currentContext(): SelfContext {
  return { modulePath: fileURLToPath(import.meta.url), execPath: process.execPath, home: defaultVaultHome() };
}

export function selfForm(modulePath: string): SelfForm {
  if (modulePath.startsWith("/$bunfs/") || /^[A-Za-z]:[\\/]~BUN[\\/]/.test(modulePath)) return "binary";
  return modulePath.endsWith(".mjs") ? "bundle" : "dev";
}

export function pinnedBinaryPath(home: string): string {
  return join(home, "bin", "secretgate");
}

export function pinnedBundlePath(home: string): string {
  return join(home, "bin", "secretgate.mjs");
}

// The program the hooks run, as a shell command prefix (`… hook <agent> <event>`
// is appended). The binary needs no runtime in front of it.
export function commandLine(inv: Invocation): string {
  return [inv.file === "node" ? "node" : `"${inv.file}"`, ...inv.args.map((a) => `"${a}"`)].join(" ");
}

// How to run THIS form of the CLI as a child process — the pinned copy when it
// exists (that is what the hooks run), else the running program itself.
export function selfInvocation(ctx: SelfContext = currentContext()): Invocation {
  const form = selfForm(ctx.modulePath);
  if (form === "binary") {
    const pinned = pinnedBinaryPath(ctx.home);
    return { file: existsSync(pinned) ? pinned : ctx.execPath, args: [] };
  }
  if (form === "bundle") {
    const pinned = pinnedBundlePath(ctx.home);
    return { file: "node", args: [existsSync(pinned) ? pinned : ctx.modulePath] };
  }
  return { file: "node", args: [join(dirname(ctx.modulePath), "main.ts")] };
}

function samePath(a: string, b: string): boolean {
  try {
    return realpathSync(a) === realpathSync(b);
  } catch {
    return false;
  }
}

// Replace `target` atomically: a hook may be executing the old copy right now,
// and truncating a file in place under it crashes that hook (fail-open) — or,
// for a signed macOS binary, gets the process killed.
function atomicCopy(source: string, target: string): void {
  const tmp = `${target}.${process.pid}.tmp`;
  try {
    copyFileSync(source, tmp);
    chmodSync(tmp, 0o755);
    renameSync(tmp, target);
  } catch (err) {
    rmSync(tmp, { force: true });
    throw err;
  }
}

// The hook command must keep working after npx caches are evicted, packages
// update, or `brew cleanup` deletes the Cellar version that ran `init` — so pin
// a copy of the running program under the secretgate home and reference that
// absolute path. Re-running `init` after an update refreshes the copy.
export function pinSelf(ctx: SelfContext = currentContext()): Invocation {
  const form = selfForm(ctx.modulePath);
  if (form === "dev") return selfInvocation(ctx);
  const [source, target] = form === "binary" ? [ctx.execPath, pinnedBinaryPath(ctx.home)] : [ctx.modulePath, pinnedBundlePath(ctx.home)];
  mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
  if (!samePath(source, target)) atomicCopy(source, target);
  return form === "binary" ? { file: target, args: [] } : { file: "node", args: [target] };
}

// The program a wired hook command runs: its first quoted word, else its first
// word after a JS runtime (`node x.mjs hook …`).
export function hookProgram(command: string): string | undefined {
  const quoted = /^\s*(?:(?:node|nodejs|bun)\s+)?"([^"]+)"/.exec(command)?.[1];
  if (quoted) return quoted;
  const words = command.trim().split(/\s+/);
  const first = words[0] && /^(?:node|nodejs|bun)$/.test(basename(words[0])) ? words[1] : words[0];
  return first && first !== "hook" ? first : undefined;
}
