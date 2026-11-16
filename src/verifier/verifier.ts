import { isAllowedValue, isDisabledRule, type UserAllowlist } from "../engine/allowlist.js";
import { shannonEntropy } from "../engine/entropy.js";
import type { Finding } from "../engine/scanner.js";
import { type AssetName, readAsset } from "./assets.js";
import { VERIFIER_RULE_ID } from "./common.js";
export { debugFromEnv, repositoryPath, VERIFIER_HARD_MS, VERIFIER_RULE_ID } from "./common.js";
import type { ThresholdPreset, VerifierConfig } from "./config.js";
import { type CandidateRecord, candidateRecords, genericKeywordCost } from "./generator.js";
import { verifierFromModule, type WasmModule, type WasmVerifier, webAssembly } from "./host.js";

// The experimental verifier (opt-in, off by default): the model
// s6-secrets-verify-pico judges the candidates of the frozen generator
// `sg-cand-1` that no finding of the default engine covers, and a candidate it
// accepts (P(real credential) >= the threshold stored in the model) is redacted
// like a finding, under its own rule id. See docs/verifier.md.
//
// What it may never do:
//   - remove, weaken or delay a rule finding: it runs after the rules, only on
//     what they left, and its time is not taken from theirs;
//   - stop, block or fail anything: every failure (no assets, a file that is
//     not the pinned one, a WebAssembly error, its budget running out) skips
//     it, and the text goes on exactly as the rules left it.

// ---------------------------------------------------------------- budget
// The generator and the model run in a child process of this same program
// (src/verifier/child.ts), killed at a hard deadline: the rules' result is
// computed first and never waits on the verifier longer than VERIFIER_HARD_MS.
// Inside the child, a softer budget stops judging in time to answer with what
// it judged: when it runs out, the candidates left are not judged (debug
// output says how many).

/** The child's own budget, from its start: it answers with what it judged by then. */
export const VERIFIER_BUDGET_MS = 750;
/** Candidates judged per event. */
export const VERIFIER_MAX_CANDIDATES = 200;
/** A longer string is not given to the generator. */
export const VERIFIER_MAX_TEXT = 1024 * 1024;
/** An early skip only: a string whose generic-keyword estimate is higher is not given to the generator (see genericKeywordCost). */
export const GENERIC_KEYWORD_COST_LIMIT = 50_000_000;

// ---------------------------------------------------------------- engine

export type EngineBuild = "relaxed-simd" | "simd128";

export interface VerifierEngine {
  build: EngineBuild;
  /** The threshold of the preset, from the model file. */
  tau: number;
  judge(candidate: Record<string, unknown>): number;
  /** The state text of a candidate (for the proofs). */
  state(candidate: Record<string, unknown>): string;
}

export type EngineLoader = (preset: ThresholdPreset) => VerifierEngine;

/** Thrown when the assets are not there or not the pinned files. */
export class VerifierAssetError extends Error {
  constructor(file: AssetName, state: string) {
    super(`${file} is ${state}`);
    this.name = "VerifierAssetError";
  }
}

function asset(file: AssetName, dir: string | undefined): Uint8Array {
  const read = readAsset(file, dir);
  if (!("bytes" in read)) throw new VerifierAssetError(file, read.state);
  return read.bytes;
}

/** Which build a module of this runtime compiles: the relaxed-SIMD one when the runtime validates it. */
export function compileEngine(dir?: string, force?: EngineBuild): { build: EngineBuild; module: WasmModule } {
  if (force !== "simd128") {
    const relaxed = asset("sky_web_relaxed_bg.wasm", dir);
    // Compiling validates: a runtime without relaxed SIMD refuses the module.
    try {
      return { build: "relaxed-simd", module: compileModule(relaxed) };
    } catch (err) {
      if (force === "relaxed-simd") throw err;
    }
  }
  return { build: "simd128", module: compileModule(asset("sky_web_bg.wasm", dir)) };
}

function compileModule(bytes: Uint8Array): WasmModule {
  const api = webAssembly();
  return new api.Module(bytes);
}

/** The real engine: the pinned files from secretgate's data directory, each checked again. */
export function loadEngine(preset: ThresholdPreset, opts: { dir?: string; force?: EngineBuild } = {}): VerifierEngine {
  const model = asset("s6-secrets-verify-pico.gguf", opts.dir);
  const words = asset("dictionary.txt", opts.dir);
  const { build, module } = compileEngine(opts.dir, opts.force);
  const v: WasmVerifier = verifierFromModule(module, model, words);
  const tau = v.thresholds()[`tau_${preset}`];
  if (typeof tau !== "number" || !Number.isFinite(tau) || tau <= 0 || tau > 1) {
    v.free();
    throw new Error(`the model file has no usable tau_${preset}`);
  }
  return {
    build,
    tau,
    judge: (c) => {
      const p = v.judge(c).p_real;
      if (typeof p !== "number" || !Number.isFinite(p)) throw new Error("the engine answered no probability");
      return p;
    },
    state: (c) => v.state(c),
  };
}
let defaultLoader: EngineLoader = (preset) => loadEngine(preset);

/** Replaces the engine every new session loads (tests: a fake verifier, no assets). `undefined` restores the real one. */
export function setEngineLoader(loader: EngineLoader | undefined): void {
  defaultLoader = loader ?? ((preset) => loadEngine(preset));
}

// ---------------------------------------------------------------- candidates

/** The candidate as the engine reads it: the generator's record, with the file's path when there is one. */
export function engineCandidate(record: CandidateRecord, path: string | undefined): Record<string, unknown> {
  return path === undefined ? { ...record } : { ...record, file: path };
}

// ---------------------------------------------------------------- session

export interface VerifierStats {
  strings: number;
  /** strings the generator was not run on, by reason */
  skippedStrings: Record<string, number>;
  candidates: number;
  /** candidates a rule finding overlaps: left to the rule */
  covered: number;
  /** candidates whose value the user allowlisted */
  allowlisted: number;
  judged: number;
  accepted: number;
  /** candidates left unjudged when the budget ended */
  unjudged: number;
  /** why the verifier stopped for this event, when it did */
  stopped?: string;
  build?: EngineBuild;
  loadMs?: number;
  ms: number;
}

export interface Accepted {
  finding: Finding;
  /** the generator's rule that proposed it */
  rule: string;
  p: number;
}

export interface SessionOptions {
  config: VerifierConfig;
  allowlist?: UserAllowlist;
  /** A trustworthy repository-relative path of the text (a Read's file), else none. */
  path?: string;
  loader?: EngineLoader;
  budgetMs?: number;
  maxCandidates?: number;
  /** false: give every string to the generator (tests of the hard bound) */
  earlySkip?: boolean;
  debug?: (line: string) => void;
}

/**
 * One event's verifier: its budget, its engine (loaded on the first string
 * that has a candidate to judge), its counts. `accept` never throws.
 */
export class VerifierSession {
  readonly stats: VerifierStats = {
    strings: 0,
    skippedStrings: {},
    candidates: 0,
    covered: 0,
    allowlisted: 0,
    judged: 0,
    accepted: 0,
    unjudged: 0,
    ms: 0,
  };
  readonly accepted: Accepted[] = [];
  private engine: VerifierEngine | undefined;
  private stopped: string | undefined;
  private readonly budgetMs: number;
  private readonly maxCandidates: number;
  private readonly loader: EngineLoader;
  private readonly started = performance.now();
  private readonly opts: SessionOptions;

  constructor(opts: SessionOptions) {
    this.opts = opts;
    this.budgetMs = opts.budgetMs ?? VERIFIER_BUDGET_MS;
    this.maxCandidates = opts.maxCandidates ?? VERIFIER_MAX_CANDIDATES;
    this.loader = opts.loader ?? defaultLoader;
    if (!opts.config.enabled) this.stopped = "off";
    else if (isDisabledRule(VERIFIER_RULE_ID, opts.allowlist)) this.stopped = `rule ${VERIFIER_RULE_ID} is allowlisted`;
  }

  /** Whether the verifier still runs in this event. */
  get active(): boolean {
    return this.stopped === undefined;
  }

  private stop(why: string): void {
    this.stopped ??= why;
    this.stats.stopped ??= why;
  }

  private skipString(why: string): void {
    this.stats.skippedStrings[why] = (this.stats.skippedStrings[why] ?? 0) + 1;
  }

  /**
   * The candidates of `text` the verifier accepts, as findings of
   * VERIFIER_RULE_ID, sorted by position. `covered` are the rule findings of
   * the same text: a candidate one of them overlaps is left to the rule.
   * Never throws: on any failure it returns what it accepted before it.
   */
  accept(text: string, covered: readonly Finding[]): Finding[] {
    if (this.stopped !== undefined || text.length === 0) return [];
    const t0 = performance.now();
    const out: Finding[] = [];
    try {
      this.stats.strings++;
      const end = this.started + this.budgetMs;
      if (performance.now() >= end) {
        this.stop("budget");
        return out;
      }
      if (this.opts.earlySkip !== false && text.length > VERIFIER_MAX_TEXT) {
        this.skipString("too long");
        return out;
      }
      if (this.opts.earlySkip !== false && genericKeywordCost(text) > GENERIC_KEYWORD_COST_LIMIT) {
        this.skipString("generic-keyword bound");
        return out;
      }
      // The user's allowlist goes to the frozen engine: a rule the user
      // disabled proposes nothing, an allowlisted value is no candidate.
      const records = candidateRecords(text, { reported: false, ...(this.opts.allowlist ? { allowlist: this.opts.allowlist } : {}) });
      this.stats.candidates += records.length;
      const todo: CandidateRecord[] = [];
      for (const r of records) {
        const span = { start: r.offset, end: r.offset + r.length };
        if (covered.some((f) => f.start < span.end && span.start < f.end)) this.stats.covered++;
        else if (isAllowedValue(r.value, this.opts.allowlist)) this.stats.allowlisted++;
        else todo.push(r);
      }
      if (todo.length === 0) return out;
      if (this.engine === undefined) {
        const l0 = performance.now();
        try {
          this.engine = this.loader(this.opts.config.threshold);
        } catch (err) {
          this.stop(err instanceof VerifierAssetError ? `assets: ${err.message}` : "engine failed to load");
          this.stats.unjudged += todo.length;
          return out;
        }
        this.stats.build = this.engine.build;
        this.stats.loadMs = performance.now() - l0;
      }
      for (let i = 0; i < todo.length; i++) {
        if (this.stats.judged >= this.maxCandidates || performance.now() >= end) {
          this.stop(this.stats.judged >= this.maxCandidates ? "candidate cap" : "budget");
          this.stats.unjudged += todo.length - i;
          break;
        }
        const r = todo[i]!;
        let p: number;
        try {
          p = this.engine.judge(engineCandidate(r, this.opts.path));
        } catch {
          // An engine that failed once is not trusted with the rest.
          this.stop("engine error");
          this.stats.unjudged += todo.length - i;
          break;
        }
        this.stats.judged++;
        // Written so that a probability that is not a number is never accepted.
        if (!(p >= this.engine.tau)) continue;
        const finding: Finding = {
          ruleId: VERIFIER_RULE_ID,
          match: r.value,
          secret: r.value,
          start: r.offset,
          end: r.offset + r.length,
          entropy: shannonEntropy(r.value),
          line: r.line - 1,
        };
        this.stats.accepted++;
        this.accepted.push({ finding, rule: r.rule, p });
        out.push(finding);
      }
      return out;
    } catch {
      this.stop("internal error");
      return out;
    } finally {
      this.stats.ms += performance.now() - t0;
    }
  }

  /** One line for debug output: counts and times, never a value. */
  summary(): string {
    const s = this.stats;
    const parts = [
      `${s.strings} string(s)`,
      `${s.candidates} candidate(s)`,
      `${s.covered} left to a rule`,
      `${s.allowlisted} allowlisted`,
      `${s.judged} judged`,
      `${s.accepted} accepted`,
    ];
    if (s.unjudged > 0) parts.push(`${s.unjudged} NOT judged (${s.stopped})`);
    else if (s.stopped !== undefined) parts.push(`stopped: ${s.stopped}`);
    const skipped = Object.entries(s.skippedStrings);
    if (skipped.length > 0) parts.push(`strings skipped: ${skipped.map(([k, n]) => `${n} ${k}`).join(", ")}`);
    if (s.build !== undefined) parts.push(`engine ${s.build}, loaded in ${s.loadMs!.toFixed(1)} ms`);
    if (this.opts.path !== undefined) parts.push("with the file's path");
    parts.push(`verifier total ${s.ms.toFixed(1)} ms`);
    for (const a of this.accepted) parts.push(`accepted line ${a.finding.line + 1} (${a.rule}, p ${a.p.toFixed(3)})`);
    return parts.join("; ");
  }

  /** Writes the summary to the debug sink, if there is one and the verifier was on. */
  report(): void {
    if (this.opts.debug === undefined || this.stats.stopped === "off" || this.stopped === "off") return;
    this.opts.debug(this.summary());
  }
}
