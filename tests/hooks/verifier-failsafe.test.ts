import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import SecretgatePlugin from "../../src/adapters/opencode-plugin.js";
import { handleClaudeCode } from "../../src/hooks/claude-code.js";
import { handleCodex } from "../../src/hooks/codex.js";
import { restorePlaceholders } from "../../src/redact.js";
import { Vault } from "../../src/vault/vault.js";
import { ASSETS, assetDir, assetStates } from "../../src/verifier/assets.js";
import { setJobRunner } from "../../src/verifier/child.js";
import { recordHandled, takeHandled } from "../../src/verifier/hook.js";
import { runJob } from "../../src/verifier/job.js";
import { type EngineLoader, setEngineLoader, VERIFIER_MAX_CANDIDATES } from "../../src/verifier/verifier.js";

// The fail-safe paths of the verifier option, with a FAKE engine that accepts
// what it is asked to (no assets), the job run in this process.
const value = ["Qm7", "xR2", "pL9", "vN4", "kT8"].join("");
let home: string;
let judged: Array<Record<string, unknown>>;
const engine =
  (p: (c: Record<string, unknown>) => number): EngineLoader =>
  () => ({
    build: "simd128",
    tau: 0.5,
    judge: (c) => {
      judged.push(c);
      return p(c);
    },
    state: () => "",
  });

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "secretgate-fs-"));
  process.env.SECRETGATE_HOME = home;
  writeFileSync(join(home, "config.json"), JSON.stringify({ verifier: { enabled: true } }));
  judged = [];
  setEngineLoader(engine(() => 0.9));
  setJobRunner((job) => ({ ok: true, result: runJob(job), ms: 0 }));
});
afterEach(() => {
  setEngineLoader(undefined);
  setJobRunner(undefined);
  delete process.env.SECRETGATE_HOME;
  rmSync(home, { recursive: true, force: true });
});

const bash = (stdout: string, session = "s1") =>
  JSON.stringify({
    session_id: session,
    cwd: "/tmp",
    tool_name: "Bash",
    tool_input: { command: "env" },
    tool_response: { stdout, stderr: "", interrupted: false, isImage: false },
  });
const stdoutOf = (r: { stdout: string }): string => (r.stdout ? JSON.parse(r.stdout).hookSpecificOutput.updatedToolOutput.stdout : "");

describe("the asset directory and files (decision: accepted as they are; their bytes decide)", () => {
  // The bytes a hook uses are the bytes it hashed: each file is read once,
  // checked against its pin, and compiled from that same buffer. A symlink, a
  // file other accounts can write, or a swap can only make a file fail its
  // pin, and the verifier is then skipped. (With the real assets, a symlink
  // to the pinned file loads: tests/verifier/real-assets.test.ts.)
  it("refuses a symlink, a writable file or a swapped file that is not the pinned bytes", () => {
    mkdirSync(assetDir(), { recursive: true });
    const elsewhere = join(home, "elsewhere.bin");
    writeFileSync(elsewhere, Buffer.alloc(249_984));
    symlinkSync(elsewhere, join(assetDir(), "s6-secrets-verify-pico.gguf"));
    writeFileSync(join(assetDir(), "dictionary.txt"), Buffer.alloc(1_706_770));
    chmodSync(join(assetDir(), "dictionary.txt"), 0o666);
    // The two engine builds swapped: each has the other's size.
    writeFileSync(join(assetDir(), "sky_web_bg.wasm"), Buffer.alloc(1_219_957));
    writeFileSync(join(assetDir(), "sky_web_relaxed_bg.wasm"), Buffer.alloc(1_222_078));
    expect(assetStates().map((s) => s.state)).toEqual(["mismatch", "mismatch", "mismatch", "mismatch"]);
  });

  it("does not hang on a path that is not a file (a directory, a dangling link)", () => {
    mkdirSync(join(assetDir(), "dictionary.txt"), { recursive: true });
    symlinkSync(join(home, "nowhere"), join(assetDir(), "sky_web_bg.wasm"));
    const states = Object.fromEntries(assetStates().map((s) => [s.pin.file, s.state]));
    expect(states["dictionary.txt"]).toBe("missing");
    expect(states["sky_web_bg.wasm"]).toBe("missing");
    expect(ASSETS.length).toBe(4);
  });

  it("with the real loader and broken assets, the hook answers as with the option off", async () => {
    setEngineLoader(undefined);
    mkdirSync(assetDir(), { recursive: true });
    for (const a of ASSETS) writeFileSync(join(assetDir(), a.file), "x");
    expect(await handleClaudeCode("post-tool-use", bash(`DB_PASS=${value}\n`))).toEqual({ stdout: "", exit: 0 });
  });
});

describe("what the engine does", () => {
  it("a trap on a candidate stops it; what it accepted before stays redacted", async () => {
    let n = 0;
    setEngineLoader(
      engine(() => {
        if (n++ > 0) throw new Error("RuntimeError: unreachable executed");
        return 0.9;
      }),
    );
    const out = stdoutOf(await handleClaudeCode("post-tool-use", bash(`DB_PASS=${value}\nSMTP_PASS=${value}xy\n`)));
    expect(out.split("\n")[0]).toMatch(/^DB_PASS=SECRETGATE_/);
  });

  it("thousands of candidates: at most the cap is judged, in text order", async () => {
    const lines = Array.from({ length: 3000 }, (_, i) => `K${i}_PASS=${value}${i}`).join("\n");
    setEngineLoader(engine(() => 0.1));
    await handleClaudeCode("post-tool-use", bash(lines));
    expect(judged.length).toBe(VERIFIER_MAX_CANDIDATES);
    expect(judged.map((c) => c.offset as number)).toEqual([...judged.map((c) => c.offset as number)].sort((a, b) => a - b));
  });
});

describe("the text around a candidate", () => {
  it("CRLF: the value is redacted without its \\r, and restored as it was", async () => {
    const text = `HOME=/x\r\nDB_PASS=${value}\r\nEND=1\r\n`;
    const out = stdoutOf(await handleClaudeCode("post-tool-use", bash(text)));
    expect(out).toMatch(/^HOME=\/x\r\nDB_PASS=SECRETGATE_[0-9a-f]{12}\r\nEND=1\r\n$/);
    expect(restorePlaceholders(out, new Vault()).text).toBe(text);
  });

  it("a placeholder already there is not judged again; a value next to one is judged, redacted, and restored", async () => {
    const first = stdoutOf(await handleClaudeCode("post-tool-use", bash(`DB_PASS=${value}\n`)));
    const placeholder = /SECRETGATE_[0-9a-f]{12}/.exec(first)![0];
    judged = [];
    expect(await handleClaudeCode("post-tool-use", bash(`DB_PASS=${placeholder}\n`))).toEqual({ stdout: "", exit: 0 });
    expect(judged).toEqual([]);
    const next = `DB_PASS=${placeholder}${value}Zz\n`;
    const out = stdoutOf(await handleClaudeCode("post-tool-use", bash(next)));
    expect(out).not.toContain(value);
    expect(restorePlaceholders(out, new Vault()).text).toBe(`DB_PASS=${value}${value}Zz\n`);
  });
});

describe("concurrent hooks", () => {
  it("records of PostToolUse from concurrent hooks are all read by the batch", () => {
    const strings = Array.from({ length: 50 }, (_, i) => `out ${i}`);
    for (const s of strings) recordHandled("s1", [s]);
    const handled = takeHandled("s1");
    expect(strings.every(handled)).toBe(true);
    expect(takeHandled("s1")("out 1")).toBe(false);
    // A session id that is not a plain name records nothing (no path from it).
    recordHandled("../../etc", ["x"]);
    expect(takeHandled("../../etc")("x")).toBe(false);
  });
});

describe("the guarded commands, run by an agent", () => {
  const pre = (command: string) => JSON.stringify({ session_id: "s1", cwd: "/tmp", tool_name: "Bash", tool_input: { command } });
  it("Claude Code asks, Codex refuses, OpenCode refuses", async () => {
    for (const command of ["secretgate verifier off", "secretgate verifier on", "secretgate verifier fetch"]) {
      expect(JSON.parse((await handleClaudeCode("pre-tool-use", pre(command))).stdout).hookSpecificOutput.permissionDecision).toBe("ask");
      expect(JSON.parse((await handleCodex("pre-tool-use", pre(command))).stdout).hookSpecificOutput.permissionDecision).toBe("deny");
    }
    const hooks: Record<string, (e: unknown) => Promise<void>> = {};
    const register = async (name: string, cb: (e: unknown) => Promise<void>) => {
      hooks[name] = cb;
    };
    await SecretgatePlugin.setup({ location: { directory: home }, session: { hook: register, get: async () => ({}) }, tool: { hook: register } } as never);
    await expect(hooks["execute.before"]!({ tool: "shell", sessionID: "oc", input: { command: "secretgate verifier off" } })).rejects.toThrow(
      /run it yourself/,
    );
  });
});
