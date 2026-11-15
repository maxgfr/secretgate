import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { handleClaudeCode } from "../../src/hooks/claude-code.js";
import { assetDir } from "../../src/verifier/assets.js";
import { setJobRunner } from "../../src/verifier/child.js";
import { recordHandled, takeHandled, verifyStrings } from "../../src/verifier/hook.js";
import { runJob } from "../../src/verifier/job.js";
import { type EngineLoader, setEngineLoader } from "../../src/verifier/verifier.js";

// The second review's defects, with a FAKE engine run in this process: it
// accepts a candidate when `accept` says so.
let home: string;
let accept: (c: Record<string, unknown>) => boolean;
let judged: Array<Record<string, unknown>>;
const engine: EngineLoader = () => ({
  build: "simd128",
  tau: 0.5,
  judge: (c) => {
    judged.push(c);
    return accept(c) ? 0.9 : 0.1;
  },
  state: () => "",
});

const on = () => writeFileSync(join(home, "config.json"), JSON.stringify({ verifier: { enabled: true } }));
beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "secretgate-r4-"));
  process.env.SECRETGATE_HOME = home;
  writeFileSync(join(home, "salt"), "7".repeat(64));
  accept = () => true;
  judged = [];
  setEngineLoader(engine);
  setJobRunner((job) => ({ ok: true, result: runJob(job), ms: 0 }));
});
afterEach(() => {
  setEngineLoader(undefined);
  setJobRunner(undefined);
  delete process.env.SECRETGATE_HOME;
  rmSync(home, { recursive: true, force: true });
});

const bash = (stdout: string, stderr = "", session = "s1") =>
  JSON.stringify({
    session_id: session,
    cwd: "/tmp",
    tool_name: "Bash",
    tool_input: { command: "x" },
    tool_response: { stdout, stderr, interrupted: false, isImage: false },
  });
const out = (r: { stdout: string }) => (r.stdout ? JSON.parse(r.stdout).hookSpecificOutput.updatedToolOutput : undefined);

describe("1. a value it accepts spreads only as a whole, unusual token", () => {
  it("does not corrupt text that merely contains a short or common value", async () => {
    on();
    const stderr = "DATABASE_URL=postgresql://localhost:5432/app image: postgres:16-alpine; use the postgres_fdw extension; login as root1234567";
    for (const stdout of ["DB_PASSWORD=postgres\n", "pwd=root1234\n"]) {
      const r = out(await handleClaudeCode("post-tool-use", bash(stdout, stderr)));
      expect(r.stderr).toBe(stderr);
      expect(r.stdout).toMatch(/=SECRETGATE_[0-9a-f]{12}\n$/);
    }
  });

  it("redacts a long, mixed value where it stands alone elsewhere, never inside a longer token", async () => {
    on();
    const v = ["Hb4", "wE9", "zN2", "cK7", "qL1"].join("");
    const stderr = `using ${v} now; id x${v} and ${v}_2 and ${v}9 stay`;
    const r = out(await handleClaudeCode("post-tool-use", bash(`DB_PASS=${v}\n`, stderr)));
    expect(r.stderr).toMatch(/^using SECRETGATE_[0-9a-f]{12} now; /);
    expect(r.stderr.endsWith(`id x${v} and ${v}_2 and ${v}9 stay`)).toBe(true);
  });
});

describe("2. object keys are never judged or rewritten", () => {
  it("Read: the keys of the result stay, whatever the content says", async () => {
    on();
    const file = "/tmp/x.env";
    const r = await handleClaudeCode(
      "post-tool-use",
      JSON.stringify({
        session_id: "s1",
        cwd: "/tmp",
        tool_name: "Read",
        tool_input: { file_path: file },
        tool_response: { type: "text", file: { filePath: file, content: "DB_PASSWORD=filePath\n", numLines: 2, startLine: 1, totalLines: 2 } },
      }),
    );
    const o = out(r);
    expect(Object.keys(o.file)).toEqual(["filePath", "content", "numLines", "startLine", "totalLines"]);
    expect(o.file.filePath).toBe(file);
    expect(o.file.content).toMatch(/^DB_PASSWORD=SECRETGATE_/);
  });

  it("Bash and MCP: keys stay, and a key is never sent to the verifier", async () => {
    on();
    const b = out(await handleClaudeCode("post-tool-use", bash("PGPASSWORD=stdout\n")));
    expect(Object.keys(b)).toEqual(["stdout", "stderr", "interrupted", "isImage"]);
    const key = `DB_PASS=${["Qm7", "xR2", "pL9", "vN4", "kT8"].join("")}`;
    judged = [];
    const r = await handleClaudeCode(
      "post-tool-use",
      JSON.stringify({
        session_id: "s1",
        cwd: "/tmp",
        tool_name: "mcp__s__get",
        tool_input: {},
        tool_response: [{ type: "text", text: "DB_PASS=meta", meta: { [key]: 1 } }],
      }),
    );
    expect(judged.every((c) => !String(c.lineText).includes(key))).toBe(true);
    const o = out(r);
    expect(Object.keys(o[0])).toEqual(["type", "text", "meta"]);
    expect(o[0].text).toMatch(/^DB_PASS=SECRETGATE_/);
    expect(Object.keys(o[0].meta)).toEqual([key]);
  });
});

describe("3. one deadline for everything the verifier causes after its child", () => {
  it("the reviewer's input: one value, then 20 identical 100 KB strings ending with it", async () => {
    const PW = ["Qm7", "xR2", "pL9", "vN4", "kT8"].join("");
    const B = `${"key".repeat(34_000)} ${PW}\n`;
    const input = JSON.stringify({
      session_id: "s1",
      cwd: "/tmp",
      tool_name: "mcp__srv__get",
      tool_input: {},
      tool_response: [{ type: "text", text: `DB_PASS=${PW}\n` }, ...Array.from({ length: 20 }, () => ({ type: "text", text: B }))],
    });
    const t0 = performance.now();
    await handleClaudeCode("post-tool-use", input);
    const off = performance.now() - t0;
    on();
    const t1 = performance.now();
    const r = await handleClaudeCode("post-tool-use", input);
    const added = performance.now() - t1 - off;
    const { REDACT_AGAIN_MS } = await import("../../src/verifier/hook.js");
    expect(added, `${added.toFixed(0)} ms added`).toBeLessThanOrEqual(REDACT_AGAIN_MS + (process.env.SECRETGATE_BOUND_STRICT === "1" ? 150 : 1000));
    expect(out(r)[0].text).toMatch(/^DB_PASS=SECRETGATE_/);
  }, 60_000);
});

describe("4. the session id is never a path", () => {
  it("`.` and `..` record nothing, and the asset directory is never moved", async () => {
    mkdirSync(assetDir(), { recursive: true });
    writeFileSync(join(assetDir(), "dictionary.txt"), "x");
    for (const s of [".", "..", "a/b", "a\\b", "", "x".repeat(200), "..foo", "a..b"]) {
      recordHandled(s, ["out"]);
      expect(takeHandled(s)("out"), JSON.stringify(s)).toBe(false);
    }
    on();
    for (const s of [".", ".."])
      await handleClaudeCode(
        "post-tool-batch",
        JSON.stringify({
          session_id: s,
          cwd: "/tmp",
          tool_calls: [{ tool_name: "Bash", tool_input: {}, tool_use_id: "t", tool_response: "DB_PASSWORD=postgres\n" }],
        }),
      );
    expect(existsSync(join(assetDir(), "dictionary.txt"))).toBe(true);
    expect(readdirSync(join(home)).filter((f) => f.includes("taken"))).toEqual([]);
    expect(readdirSync(join(home, "verifier"))).toEqual([readdirSync(join(home, "verifier")).find((d) => d.startsWith("s6-"))]);
  });
});

describe("spans the parent refuses", () => {
  const answer = (spans: Array<[number, number]>) => () => ({
    ok: true as const,
    ms: 0,
    result: { v: 1 as const, accepted: spans.map(([start, end]) => ({ i: 0, start, end, rule: "x", p: 0.9 })), stats: {} as never, summary: "" },
  });
  const config = { enabled: true, threshold: "f1" as const };

  it("a span that splits a surrogate pair", () => {
    const text = "key=\u{1F511}abcdefgh";
    setJobRunner(answer([[5, 13]]));
    expect(verifyStrings([{ text, findings: [] }], { config, label: "t" }).extra.size).toBe(0);
    setJobRunner(answer([[4, 13]]));
    expect(verifyStrings([{ text, findings: [] }], { config, label: "t" }).extra.get(text)?.length).toBe(1);
  });

  it("a span inside, or cutting, an existing placeholder; one that holds a whole placeholder is kept", () => {
    const text = "x=SECRETGATE_0123456789abZZZZZZ";
    for (const span of [
      [4, 12],
      [10, 30],
    ] as Array<[number, number]>) {
      setJobRunner(answer([span]));
      expect(verifyStrings([{ text, findings: [] }], { config, label: "t" }).extra.size, String(span)).toBe(0);
    }
    setJobRunner(answer([[2, 31]]));
    expect(verifyStrings([{ text, findings: [] }], { config, label: "t" }).extra.get(text)?.length).toBe(1);
  });
});
