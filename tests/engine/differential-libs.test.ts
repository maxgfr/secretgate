import picomatch from "picomatch";
import { parse as shellParse } from "shell-quote";
import { describe, expect, it } from "vitest";
import { pathMatchesGlob } from "../../src/engine/allowlist.js";
import { analyzeShell } from "../../src/shell-paths.js";

// Hand-written matchers checked against widely used libraries on a seeded
// random corpus — the same idea as the gitleaks differential for the rules.
// The libraries are dev-only oracles; the bundle stays dependency-free.

function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 2 ** 32;
  };
}
const pick = <T>(r: () => number, xs: readonly T[]): T => xs[Math.floor(r() * xs.length)]!;

describe("pathMatchesGlob agrees with picomatch", () => {
  // Segment-level syntax both implement identically: literals, `*`, `?`,
  // whole-segment `**`, `{a,b}`. (Mid-segment `**` differs on purpose:
  // picomatch reads `a**` as `a*`, secretgate keeps its documented meaning.)
  const globSegments = ["src", "lib", "a", "*.ts", "*", "?.md", "**", "{src,lib}", ".env", "*.{ts,md}", "x-1", "b?"] as const;
  const pathSegments = ["src", "lib", "a", "b.ts", "c.md", "x.md", ".env", "x-1", "bb", "deep"] as const;

  it("on 5000 random glob/path pairs", () => {
    const r = rng(0x5ec7e7);
    const mismatches: string[] = [];
    for (let n = 0; n < 5000; n++) {
      const glob = Array.from({ length: 1 + Math.floor(r() * 4) }, () => pick(r, globSegments)).join("/");
      const path = Array.from({ length: 1 + Math.floor(r() * 5) }, () => pick(r, pathSegments)).join("/");
      // picomatch lets `b?/**` match `bb` but not `*/**` match `a` — an
      // inconsistency of its own; secretgate treats both alike.
      if (/(?:^|\/)\*\/\*\*$/.test(glob)) continue;
      const ours = pathMatchesGlob(path, glob);
      const theirs = picomatch.isMatch(path, glob, { dot: true });
      if (ours !== theirs) mismatches.push(`${glob} ~ ${path}: ours=${ours} picomatch=${theirs}`);
    }
    expect(mismatches.slice(0, 10)).toEqual([]);
  });
});

describe("the shell tokenizer agrees with shell-quote", () => {
  // Quoting and separators both handle identically.
  const words = ["cat", "ls", "grep", "-rn", "src/a.ts", "'a b'", '"c d"', "e\\ f", "'it'\"'\"'s'", '"x\\"y"', "--flag=v", "file.md", "''", "a'b'c"] as const;
  const ops = [" ; ", " && ", " || ", " | "] as const;

  const theirs = (cmd: string): string[][] => {
    const out: string[][] = [[]];
    for (const t of shellParse(cmd)) {
      if (typeof t === "string") out[out.length - 1]!.push(t);
      else if ("op" in t) out.push([]);
    }
    return out.filter((c) => c.length > 0);
  };

  it("on 3000 random commands (argv per simple command)", () => {
    const r = rng(0xc0ffee);
    const mismatches: string[] = [];
    for (let n = 0; n < 3000; n++) {
      const commands = Array.from({ length: 1 + Math.floor(r() * 3) }, () => Array.from({ length: 1 + Math.floor(r() * 4) }, () => pick(r, words)).join(" "));
      let cmd = commands[0]!;
      for (const c of commands.slice(1)) cmd += pick(r, ops) + c;
      const ours = analyzeShell(cmd, { cwd: "/tmp" }).commands;
      const ref = theirs(cmd);
      if (JSON.stringify(ours) !== JSON.stringify(ref)) mismatches.push(`${cmd}\n  ours=${JSON.stringify(ours)}\n  shell-quote=${JSON.stringify(ref)}`);
    }
    expect(mismatches.slice(0, 5)).toEqual([]);
  });
});
