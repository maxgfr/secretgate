import { appendFileSync, writeSync } from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { repositoryRoot } from "../paths.js";

// What the hook side of the verifier needs without loading the generator, the
// frozen engine or the WebAssembly host (those run in its child process).

export const VERIFIER_RULE_ID = "verifier:s6-secrets";

/** Hard wall-clock bound of the verifier per hook event, the child's start-up included. */
export const VERIFIER_HARD_MS = 1000;

/**
 * A path the hook can trust (the file a Read named), relative to its
 * repository, `/`-separated, as the model was trained with CredData's paths.
 * Undefined when the file is outside the repository (or the working
 * directory when there is none): an absolute path would bring the words of
 * the directories above it into the model's scope.
 */
export function repositoryPath(file: unknown, cwd: string): string | undefined {
  if (typeof file !== "string" || file.length === 0) return undefined;
  const abs = resolve(cwd, file);
  const root = repositoryRoot(cwd) ?? resolve(cwd);
  const rel = relative(root, abs);
  if (rel === "" || rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) return undefined;
  return rel.split(sep).join("/");
}

/** `SECRETGATE_DEBUG=verifier` (or `1`/`all`) writes what the verifier did, never a value, to stderr. */
export function debugFromEnv(): ((line: string) => void) | undefined {
  const d = process.env.SECRETGATE_DEBUG ?? "";
  if (!/(?:^|,)(?:verifier|1|all)(?:,|$)/.test(d)) return undefined;
  // Synchronous, and a failed write is dropped: debug output must never be
  // what makes a hook fail (an asynchronous EPIPE on stderr would crash it).
  // SECRETGATE_DEBUG_FILE appends there instead (a host may swallow a hook's stderr).
  const file = process.env.SECRETGATE_DEBUG_FILE;
  return (line) => {
    try {
      if (file) appendFileSync(file, `secretgate verifier: ${line}\n`, { mode: 0o600 });
      else writeSync(2, `secretgate verifier: ${line}\n`);
    } catch {
      // nowhere to report to
    }
  };
}
