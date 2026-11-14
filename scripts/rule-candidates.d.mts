// Hand-written declarations so TypeScript tests can import the dev-time
// candidate export (plain ESM, not part of the bundle).
export interface Engine {
  scan(text: string, cfg?: { pragmas?: boolean; sourcePath?: string }): Array<{ ruleId: string; start: number; end: number }>;
  rulePatterns(): Array<{ id: string; re: RegExp; secretGroup?: number }>;
}

interface Traced {
  ruleId: string;
  match: string;
  secret: string;
  start: number;
  end: number;
  entropy: number;
  line: number;
  gates: string[];
}

/** What the candidate mode needs of src/engine/scanner.ts. */
export interface TraceEngine {
  scan(text: string, cfg?: { pragmas?: boolean; sourcePath?: string }): Array<{ ruleId: string; start: number; end: number }>;
  traceMatches(
    text: string,
    cfg?: { pragmas?: boolean; sourcePath?: string },
    extraRules?: Array<{ id: string; re: RegExp; keywords: string[]; nameTrusting?: boolean }>,
  ): Traced[];
  dedupeFindings<F extends { ruleId: string; match: string; secret: string; start: number; end: number; entropy: number; line: number }>(findings: F[], text: string): F[];
}

export interface CandidateRecord {
  generator: "sg-cand-1";
  file: string | null;
  ext: string;
  rule: string;
  line: number;
  start: number;
  end: number;
  cpStart: number;
  cpEnd: number;
  endLine: number;
  offset: number;
  length: number;
  value: string;
  name: string | null;
  lineText: string;
  lineFrom: number;
  prevLine: string | null;
  nextLine: string | null;
  entropy: number;
  filters: { entropy: boolean; placeholder: boolean; allowlist: boolean; stopword: boolean; context: boolean; pragma: boolean };
  reported: boolean;
  masked: boolean;
}

export interface DroppedMatch {
  rule: string;
  gate: string;
  line: number;
  start: number;
  end: number;
  endLine: number;
  offset: number;
  length: number;
}

export interface Candidate {
  mode: "rule" | "generic";
  rule: string;
  line: number;
  start: number;
  end: number;
  length: number;
  match: { start: number; end: number } | null;
  groups: Array<[number, number] | null>;
  name: string | null;
  entropy: number;
  classes: { lower: number; upper: number; digit: number; other: number };
  context: { start: number; before: string; value: string; after: string };
  masked: boolean;
}

export interface GenericCandidate {
  start: number;
  end: number;
  kind: "candidate:assignment" | "candidate:auth-header";
  name: string;
  match: [number, number];
  groups: Array<[number, number] | null>;
}

export const DEFAULT_EXTENSIONS: Set<string>;
export function newMaskKey(): Buffer;
export function maskValue(value: string, key: Buffer | string): string;
export function valueIndex(values: Iterable<string>): Map<string, string[]>;
export function maskAll(text: string, index: Map<string, string[]> | undefined, key: Buffer | string): string;
export function maskName(name: string, key: Buffer | string): string;
export function maskKnown(text: string, index: Map<string, string[]> | undefined, key: Buffer | string): string;
export function charClasses(value: string): { lower: number; upper: number; digit: number; other: number };
export function shannonEntropy(value: string): number;
export function assignedName(text: string, valueStart: number): string | undefined;
export function genericCandidates(text: string): GenericCandidate[];
export function candidatesOf(
  text: string,
  engine: Engine,
  opts?: { generic?: boolean; context?: number; raw?: boolean; maskKey?: Buffer | string; known?: Map<string, string[]> },
): Candidate[];
export const GENERATOR: "sg-cand-1";
export const GENERIC_KEYWORD: { id: "generic-keyword"; keywords: string[]; nameTrusting: true; re: RegExp };
export function candidateRecords(
  text: string,
  engine: TraceEngine,
  opts?: { sourcePath?: string; raw?: boolean; maskKey?: Buffer | string; known?: Map<string, string[]>; maxLine?: number; dropped?: DroppedMatch[] },
): CandidateRecord[];
export function walkFiles(root: string, opts?: { allText?: boolean }): Generator<string>;
export function readText(file: string, maxBytes?: number, skipped?: Record<string, number>): string | undefined;
