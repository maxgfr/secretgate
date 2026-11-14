// Hand-written declarations so TypeScript tests can import the dev-time
// candidate export (plain ESM, not part of the bundle).
export interface Engine {
  scan(text: string, cfg?: { pragmas?: boolean }): Array<{ ruleId: string; start: number; end: number }>;
  rulePatterns(): Array<{ id: string; re: RegExp; secretGroup?: number }>;
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
export function walkFiles(root: string, opts?: { allText?: boolean }): Generator<string>;
export function readText(file: string, maxBytes?: number): string | undefined;
