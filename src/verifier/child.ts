import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import { currentContext, type Invocation, runningInvocation, selfForm } from "../self.js";
import type { JobResult, VerifierJob } from "./job.js";

// The verifier's hard bound. The generator's frozen regexes and the model run
// in a child process of this same program (`secretgate __verifier-job`: the
// Node bundle under the same node, or the Bun-compiled binary itself), and the
// parent waits for it at most `hardMs`, then kills it (SIGKILL). A regex no
// deadline can interrupt, a model that loops or grows its memory without end:
// whatever it is, it is the child's, and the hook goes on with the rules'
// result. A worker thread starts faster (about 10 ms against 30 ms here), but
// Bun did not interrupt a worker stuck in a regex, and a worker shares the
// hook's memory; a process does neither.

export type JobOutcome = { ok: true; result: JobResult; ms: number } | { ok: false; why: string; ms: number };
export type JobRunner = (job: VerifierJob, hardMs: number) => JobOutcome;

/** How to run this program as the verifier's child. */
export function childInvocation(): Invocation {
  const ctx = currentContext();
  if (selfForm(ctx.modulePath) !== "dev") return runningInvocation(ctx);
  // From the sources (tests, Node >= 22.18): Node transforms the types, a hook resolves `.js` to `.ts`.
  const src = dirname(ctx.modulePath);
  return {
    file: process.execPath,
    args: [
      "--experimental-transform-types",
      "--no-warnings",
      "--import",
      pathToFileURL(join(src, "..", "scripts", "ts-resolve.mjs")).href,
      join(src, "main.ts"),
    ],
  };
}

const isResult = (v: unknown): v is JobResult => {
  const r = v as JobResult | null;
  return (
    r !== null &&
    typeof r === "object" &&
    r.v === 1 &&
    Array.isArray(r.accepted) &&
    r.accepted.every(
      (a) => Number.isInteger(a?.i) && Number.isInteger(a.start) && a.start >= 0 && Number.isInteger(a.end) && a.end > a.start && typeof a.rule === "string",
    ) &&
    typeof r.summary === "string"
  );
};

/** Runs the job in a child process, killed at `hardMs`. Never throws. */
export function spawnJob(job: VerifierJob, hardMs: number, inv: Invocation = childInvocation()): JobOutcome {
  const t0 = performance.now();
  const ms = () => performance.now() - t0;
  try {
    const r = spawnSync(inv.file, [...inv.args, "__verifier-job"], {
      input: JSON.stringify(job),
      timeout: hardMs,
      killSignal: "SIGKILL",
      maxBuffer: 64 * 1024 * 1024,
      windowsHide: true,
      encoding: "utf8",
    });
    if (r.error) return { ok: false, why: (r.error as NodeJS.ErrnoException).code === "ETIMEDOUT" ? "hard bound" : "could not start", ms: ms() };
    if (r.signal) return { ok: false, why: `killed (${r.signal})`, ms: ms() };
    if (r.status !== 0) return { ok: false, why: `exit ${r.status}`, ms: ms() };
    const parsed: unknown = JSON.parse(r.stdout);
    return isResult(parsed) ? { ok: true, result: parsed, ms: ms() } : { ok: false, why: "malformed answer", ms: ms() };
  } catch {
    return { ok: false, why: "malformed answer", ms: ms() };
  }
}

let runner: JobRunner = (job, hardMs) => spawnJob(job, hardMs);

/** The runner every hook uses (tests: run the job in-process with a fake engine). `undefined` restores the child process. */
export function setJobRunner(r: JobRunner | undefined): void {
  runner = r ?? ((job, hardMs) => spawnJob(job, hardMs));
}

export function runJobBounded(job: VerifierJob, hardMs: number): JobOutcome {
  try {
    return runner(job, hardMs);
  } catch {
    return { ok: false, why: "runner error", ms: 0 };
  }
}
