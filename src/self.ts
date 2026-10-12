import { chmodSync, copyFileSync, existsSync, mkdirSync, realpathSync, renameSync, rmSync } from "node:fs";
import { basename, delimiter, dirname, isAbsolute, join } from "node:path";
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
  const modulePath = fileURLToPath(import.meta.url);
  const execPath = selfForm(modulePath) === "binary" ? process.execPath : stableRuntime(process.execPath);
  return { modulePath, execPath, home: defaultVaultHome() };
}

// Where package managers keep a version-independent link to node. PATH can
// hold other entries that lead to the same binary — fnm's per-shell
// `fnm_multishells/<pid>/bin`, gone when that shell exits — so only these count.
const STABLE_BIN_DIRS = ["/opt/homebrew/bin", "/usr/local/bin", "/home/linuxbrew/.linuxbrew/bin", "/opt/local/bin", "/usr/bin", "/snap/bin"];

/**
 * The spelling of the running node that survives its upgrades. Homebrew
 * reports the versioned Cellar path, which `brew upgrade node` deletes — a
 * hook wired to it would exit 127 (fail open) after the next upgrade, while
 * /opt/homebrew/bin/node stays. A stable directory on PATH that leads to the
 * same binary wins; otherwise the binary itself.
 */
export function stableRuntime(execPath: string, pathEnv = process.env.PATH ?? "", stableDirs = STABLE_BIN_DIRS): string {
  let real: string;
  try {
    real = realpathSync(execPath);
  } catch {
    return execPath;
  }
  const stable = new Set(stableDirs);
  for (const dir of pathEnv.split(delimiter)) {
    if (!stable.has(dir)) continue;
    for (const name of [basename(execPath), "node"]) {
      const candidate = join(dir, name);
      try {
        if (isAbsolute(candidate) && realpathSync(candidate) === real) return candidate;
      } catch {
        // not there
      }
    }
  }
  return execPath;
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
// is appended). The binary needs no runtime in front of it; the bundle names
// the node that installed it by its absolute path — an agent started from a
// GUI may not have nvm's `node` on its PATH, and a hook that exits 127 fails
// open.
export function commandLine(inv: Invocation): string {
  return [inv.file === "node" ? "node" : `"${inv.file}"`, ...inv.args.map((a) => `"${a}"`)].join(" ");
}

// How to run THIS form of the CLI as a child process — the pinned copy when it
// exists (that is what the hooks run), else the running program itself.
export function selfInvocation(ctx: SelfContext = currentContext()): Invocation {
  const form = selfForm(ctx.modulePath);
  const pinned = form === "binary" ? pinnedBinaryPath(ctx.home) : form === "bundle" ? pinnedBundlePath(ctx.home) : undefined;
  if (pinned && existsSync(pinned)) return form === "binary" ? { file: pinned, args: [] } : { file: ctx.execPath, args: [pinned] };
  return runningInvocation(ctx);
}

// The running program itself, whatever is pinned. For checks that need this
// version's commands: the pinned copy can be older when `init` did not re-pin
// it (`init --opencode` wires no hook).
export function runningInvocation(ctx: SelfContext = currentContext()): Invocation {
  const form = selfForm(ctx.modulePath);
  if (form === "binary") return { file: ctx.execPath, args: [] };
  if (form === "bundle") return { file: ctx.execPath, args: [ctx.modulePath] };
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
  return form === "binary" ? { file: target, args: [] } : { file: ctx.execPath, args: [target] };
}

const JS_RUNTIME = /^(?:node|nodejs|bun)(?:\.exe)?$/;

// The words of a wired hook command before `hook <agent> <event>`, quotes removed.
function commandWords(command: string): string[] {
  return [...command.matchAll(/"([^"]*)"|(\S+)/g)].map((m) => m[1] ?? m[2]!);
}

// The program a wired hook command runs: the pinned binary, or the script a
// JS runtime runs (`node x.mjs hook …`, `"/abs/node" "x.mjs" hook …`).
export function hookProgram(command: string): string | undefined {
  const words = commandWords(command);
  const first = words[0] && JS_RUNTIME.test(basename(words[0])) ? words[1] : words[0];
  return first && first !== "hook" ? first : undefined;
}

/** The JS runtime a wired hook command starts (`node`, `/abs/node`), if any. */
export function hookRuntime(command: string): string | undefined {
  const first = commandWords(command)[0];
  return first && JS_RUNTIME.test(basename(first)) ? first : undefined;
}
