import type { UserAllowlist } from "../engine/allowlist.js";
import type { Finding } from "../engine/scanner.js";
import type { ThresholdPreset } from "./config.js";
import { type EngineLoader, VERIFIER_BUDGET_MS, VERIFIER_MAX_CANDIDATES, VerifierSession, type VerifierStats } from "./verifier.js";

// One hook event's work for the verifier, as the child process receives it on
// stdin (`secretgate __verifier-job`) and answers it on stdout: the strings of
// the event, the rule findings of each (a candidate one overlaps is left to
// the rule), and what the session needs. The child runs the generator and the
// model; the parent (src/verifier/child.ts) kills it at the hard bound.

export interface VerifierJob {
  v: 1;
  texts: string[];
  /** per text, the [start, end) spans of its rule findings */
  covered: Array<Array<[number, number]>>;
  threshold: ThresholdPreset;
  allowlist?: UserAllowlist;
  path?: string;
  budgetMs?: number;
  maxCandidates?: number;
  /** false: no early skip of a string (tests of the hard bound) */
  earlySkip?: boolean;
}

export interface JobAccepted {
  /** index of the text */
  i: number;
  start: number;
  end: number;
  /** the generator's rule that proposed it */
  rule: string;
  p: number;
}

export interface JobResult {
  v: 1;
  accepted: JobAccepted[];
  stats: VerifierStats;
  summary: string;
}

/** Runs a job in this process. Never throws for what the texts hold; a malformed job throws. */
export function runJob(job: VerifierJob, loader?: EngineLoader): JobResult {
  if (job?.v !== 1 || !Array.isArray(job.texts) || !Array.isArray(job.covered) || job.covered.length !== job.texts.length)
    throw new Error("not a verifier job");
  const session = new VerifierSession({
    config: { enabled: true, threshold: job.threshold },
    ...(job.allowlist ? { allowlist: job.allowlist } : {}),
    ...(job.path !== undefined ? { path: job.path } : {}),
    ...(loader ? { loader } : {}),
    budgetMs: job.budgetMs ?? VERIFIER_BUDGET_MS,
    maxCandidates: job.maxCandidates ?? VERIFIER_MAX_CANDIDATES,
    ...(job.earlySkip === false ? { earlySkip: false } : {}),
  });
  const accepted: JobAccepted[] = [];
  job.texts.forEach((text, i) => {
    const covered: Finding[] = job.covered[i]!.map(([start, end]) => ({ ruleId: "", match: "", secret: "", start, end, entropy: 0, line: 0 }));
    const before = session.accepted.length;
    session.accept(text, covered);
    for (const a of session.accepted.slice(before)) accepted.push({ i, start: a.finding.start, end: a.finding.end, rule: a.rule, p: a.p });
  });
  return { v: 1, accepted, stats: session.stats, summary: session.summary() };
}

/** `secretgate __verifier-job`: a job on stdin, its result on stdout (internal: the hooks run it). */
export async function cmdVerifierJob(read: () => Promise<string>, write: (s: string) => void): Promise<number> {
  let job: VerifierJob;
  try {
    job = JSON.parse(await read()) as VerifierJob;
  } catch {
    return 2;
  }
  write(JSON.stringify(runJob(job)));
  return 0;
}
