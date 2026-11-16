import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { handleClaudeCode } from "../../src/hooks/claude-code.js";
import { setScanDeadlineMs } from "../../src/hooks/scan-budget.js";
import { spawnJob, setJobRunner } from "../../src/verifier/child.js";
import { FAKE } from "../fixtures/fake-tokens.js";

// The verifier's time is bounded by construction: whatever the generator or
// the model does, a hook with the option on returns within the hard bound of
// what it takes with the option off, and when the bound is hit its answer is
// the option-off answer. These run the REAL generator in its child process
// (no model assets are needed: the generator runs first, on inputs where its
// frozen generic-keyword regex is quadratic).

let home: string;
beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "secretgate-bound-"));
  process.env.SECRETGATE_HOME = home;
});
afterEach(() => {
  delete process.env.SECRETGATE_HOME;
  rmSync(home, { recursive: true, force: true });
});

// The margin over the bound for the kill and for a hook's own scheduling:
// 150 ms when this file runs alone (SECRETGATE_BOUND_STRICT=1, as the
// measurements of docs/verifier.md were made), 1 s inside a parallel suite on
// a loaded machine, where any timer can fire late.
const STRICT = process.env.SECRETGATE_BOUND_STRICT === "1";
const SLACK = STRICT ? 150 : 1000;

// The bound is wall-clock time, enforced by the OS: the child is SIGKILLed when
// the timer of the hook's spawn fires. On a machine starved of CPU that timer
// fires late for any process, the hook's or not. So a child time over the
// bound counts against the hook only when a bare child, killed by the same
// kind of timer at the same bound right afterwards, is not as late: then the
// lateness is the hook's own. (Not under SECRETGATE_BOUND_STRICT=1, where the
// bound plus 150 ms is required as such.)
function bareKillMs(hardMs: number): number {
  const t0 = performance.now();
  spawnSync(process.execPath, ["-e", "for(;;){}"], { timeout: hardMs, killSignal: "SIGKILL" });
  return performance.now() - t0;
}
function expectWithinBound(ms: number, hardMs: number): void {
  if (ms <= hardMs + SLACK || STRICT) {
    expect(ms).toBeLessThanOrEqual(hardMs + SLACK);
    return;
  }
  const bare = bareKillMs(hardMs);
  expect(ms, `the child took ${ms.toFixed(0)} ms; a bare child killed at the same bound took ${bare.toFixed(0)} ms`).toBeLessThanOrEqual(bare + SLACK);
}

const k = (n: number) => "key".repeat(n);
// The reviewer's hook inputs and their regex-only shapes, then other quadratic
// shapes of the same rule: long names, many separators, quotes, a long line
// whose keyword comes at the end, 2 MiB.
const SHAPES: Record<string, string> = {
  "review: key x5000, =, 1,030,000 spaces (Read)": `${k(5000)}=${" ".repeat(1_030_000)}\nT=${FAKE.githubPat}\n`,
  "review: key x4000, =, 100,000 spaces": `${k(4000)}=${" ".repeat(100_000)}`,
  "review: key x4000, 100,000 spaces": `${k(4000)}${" ".repeat(100_000)}`,
  "review: key x2000, 300,000 tabs": `${k(2000)}${"\t".repeat(300_000)}`,
  "review: key x1000, quote, 100,000 spaces": `${k(1000)}"${" ".repeat(100_000)}`,
  "a long name run with keywords": `${"api_key_token.".repeat(40_000)}=x`,
  "many separators": "key=".repeat(250_000),
  "nested and escaped quotes": `${'key=\\"'.repeat(60_000)}${'"'.repeat(60_000)}`,
  "a 1 MiB line whose keyword comes at the end": `${"a".repeat(1024 * 1024)} key = ${" ".repeat(200_000)}`,
  "2 MiB of keywords": k(Math.floor((2 * 1024 * 1024 - 64) / 3)),
};

const read = (content: string) =>
  JSON.stringify({
    session_id: "s1",
    cwd: "/tmp",
    tool_name: "Read",
    tool_input: { file_path: "/tmp/a.txt" },
    tool_response: { type: "text", file: { filePath: "/tmp/a.txt", content, numLines: 1, startLine: 1, totalLines: 1 } },
  });
const bash = (stdout: string) =>
  JSON.stringify({
    session_id: "s1",
    cwd: "/tmp",
    tool_name: "Bash",
    tool_input: { command: "cat a" },
    tool_response: { stdout, stderr: "", interrupted: false, isImage: false },
  });
const batch = (out: string) =>
  JSON.stringify({
    session_id: "s1",
    cwd: "/tmp",
    tool_calls: [{ tool_name: "Bash", tool_input: {}, tool_use_id: "t", tool_response: `Exit code 1\n${out}` }],
  });

async function timed(event: string, input: string): Promise<{ ms: number; stdout: string; exit: number }> {
  const t0 = performance.now();
  const r = await handleClaudeCode(event, input);
  return { ms: performance.now() - t0, ...r };
}

// The rules' own budget (5 s per tool output, fail closed past it) is lifted
// here: some of these shapes take the rules about that long, so the answer of
// a run (the rules' result, or the fail-closed one) would depend on the
// machine's speed, and two runs could differ with the verifier doing nothing.
// With it lifted, every run reaches the verifier and both answers are the
// rules' result. What happens past the rules' budget is checked below, on a
// budget that is always spent.
for (const earlySkip of [true, false])
  describe(`the verifier's hard bound${earlySkip ? "" : ", with the early skip turned off (the kill alone holds it)"}`, () => {
    beforeEach(() => {
      setScanDeadlineMs(Number.POSITIVE_INFINITY);
      setJobRunner(earlySkip ? undefined : (job, ms) => spawnJob({ ...job, earlySkip: false }, ms));
    });
    afterEach(() => {
      setJobRunner(undefined);
      setScanDeadlineMs(undefined);
    });
    for (const [name, text] of Object.entries(SHAPES)) {
      for (const [event, make] of [
        ["post-tool-use", read],
        ["post-tool-use", bash],
        ["post-tool-batch", batch],
      ] as const) {
        it(`${name}: ${event} ${make === read ? "Read" : make === bash ? "Bash" : ""} adds at most the bound, and answers as with the option off`, async () => {
          const { VERIFIER_HARD_MS } = await import("../../src/verifier/verifier.js");
          // One home per run (a stopped session stays stopped), one salt for both.
          const run = async (on: boolean) => {
            const h = join(home, on ? "on" : "off");
            mkdirSync(h, { recursive: true });
            writeFileSync(join(h, "salt"), "0".repeat(64));
            if (on) writeFileSync(join(h, "config.json"), JSON.stringify({ verifier: { enabled: true } }));
            process.env.SECRETGATE_HOME = h;
            return timed(event, make(text));
          };
          const off = await run(false);
          const log = join(home, "debug.log");
          process.env.SECRETGATE_DEBUG = "verifier";
          process.env.SECRETGATE_DEBUG_FILE = log;
          const on = await run(true).finally(() => {
            delete process.env.SECRETGATE_DEBUG;
            delete process.env.SECRETGATE_DEBUG_FILE;
          });
          // The child's time, as the hook measured it (spawn to answer or kill).
          const child = [...(existsSync(log) ? readFileSync(log, "utf8") : "").matchAll(/(?:answered in|after) (\d+) ms/g)].map((m) => Number(m[1]));
          // (At the batch gate a rule finding stops the turn and the verifier does not run.)
          if (!off.stdout.includes('"continue":false')) expect(child.length, "the verifier ran").toBeGreaterThan(0);
          // The rules' budget is lifted: no answer is the fail-closed one.
          expect(off.stdout).not.toContain("could not scan this safely");
          for (const ms of child) expectWithinBound(ms, VERIFIER_HARD_MS);
          // And the whole hook: the bound, the re-redaction budget, and the noise
          // of two runs of the rules over the same text.
          expect(on.ms - off.ms, `${on.ms.toFixed(0)} ms on, ${off.ms.toFixed(0)} ms off`).toBeLessThanOrEqual(VERIFIER_HARD_MS + 250 + SLACK + off.ms);
          expect(on.exit).toBe(off.exit);
          // The placeholders are the same values under the same salt.
          expect(on.stdout).toBe(off.stdout);
          expect(on.stdout).not.toContain(FAKE.githubPat);
        }, 60_000);
      }
    }
  });

describe("past the rules' budget, the verifier changes nothing", () => {
  // A budget that is always spent (0 ms): the rules fail closed at the first
  // string, whatever the machine. With the verifier on, the answer must be
  // that same fail-closed answer, never an empty one, and the verifier does
  // not run.
  beforeEach(() => setScanDeadlineMs(0));
  afterEach(() => setScanDeadlineMs(undefined));
  for (const [event, make] of [
    ["post-tool-use", read],
    ["post-tool-use", bash],
    ["post-tool-batch", batch],
  ] as const) {
    it(`${event} ${make === read ? "Read" : make === bash ? "Bash" : ""}: the fail-closed answer, with the option on as off`, async () => {
      const text = SHAPES["2 MiB of keywords"]!;
      const run = async (on: boolean) => {
        const h = join(home, on ? "on" : "off");
        mkdirSync(h, { recursive: true });
        writeFileSync(join(h, "salt"), "0".repeat(64));
        if (on) writeFileSync(join(h, "config.json"), JSON.stringify({ verifier: { enabled: true } }));
        process.env.SECRETGATE_HOME = h;
        return handleClaudeCode(event, make(text));
      };
      const off = await run(false);
      const log = join(home, "debug.log");
      process.env.SECRETGATE_DEBUG = "verifier";
      process.env.SECRETGATE_DEBUG_FILE = log;
      const on = await run(true).finally(() => {
        delete process.env.SECRETGATE_DEBUG;
        delete process.env.SECRETGATE_DEBUG_FILE;
      });
      expect(off.stdout).not.toBe("");
      expect(off.stdout).toMatch(event === "post-tool-batch" ? /"continue":false/ : /could not scan this safely .* tool output withheld/);
      expect(on.stdout).toBe(off.stdout);
      expect(on.exit).toBe(off.exit);
      expect(existsSync(log) ? readFileSync(log, "utf8") : "").not.toMatch(/answered in|NOTHING judged/);
    });
  }
});

describe("the child process, whatever it does", () => {
  const job = { v: 1 as const, texts: ["DB_PASS=x"], covered: [[]], threshold: "f1" as const };
  const node = (code: string) => ({ file: process.execPath, args: ["-e", code] });
  const cases: Record<string, string> = {
    "loops forever": "for(;;){}",
    "grows its memory without end": "const a=[];for(;;)a.push(new Uint8Array(1<<24).fill(1))",
    "ignores SIGTERM": "process.on('SIGTERM',()=>{});setInterval(()=>{},1000)",
    "exits non-zero": "process.exit(3)",
    "answers garbage": "process.stdout.write('{not json')",
    "answers spans outside the text": "process.stdout.write(JSON.stringify({v:1,accepted:[{i:0,start:-1,end:2,rule:'x',p:1}],summary:''}))",
    "is killed by a signal": "process.kill(process.pid,'SIGSEGV')",
  };
  for (const [name, code] of Object.entries(cases)) {
    it(`${name}: no answer, within the bound`, async () => {
      const { VERIFIER_HARD_MS } = await import("../../src/verifier/verifier.js");
      const out = spawnJob(job, VERIFIER_HARD_MS, node(code));
      expect(out.ok).toBe(false);
      expectWithinBound(out.ms, VERIFIER_HARD_MS);
    }, 30_000);
  }

  it("a hook whose child loops answers as with the option off, within the bound", async () => {
    const { VERIFIER_HARD_MS } = await import("../../src/verifier/verifier.js");
    const input = bash(`DB_PASS=${["Qm7", "xR2", "pL9", "vN4", "kT8"].join("")}\nT=${FAKE.githubPat}\n`);
    const off = await timed("post-tool-use", input);
    writeFileSync(join(home, "config.json"), JSON.stringify({ verifier: { enabled: true } }));
    setJobRunner((j, ms) => spawnJob(j, ms, node("for(;;){}")));
    try {
      const on = await timed("post-tool-use", input);
      expect(on.stdout).toBe(off.stdout);
      expect(on.ms - off.ms).toBeLessThanOrEqual(VERIFIER_HARD_MS + SLACK);
    } finally {
      setJobRunner(undefined);
    }
  }, 30_000);
});
