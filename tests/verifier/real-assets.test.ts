import { spawn } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { handleClaudeCode } from "../../src/hooks/claude-code.js";
import { Vault } from "../../src/vault/vault.js";
import { ASSETS, assetDir, assetStates } from "../../src/verifier/assets.js";
import { candidateRecords } from "../../src/verifier/generator.js";
import { loadEngine, VERIFIER_RULE_ID, VerifierSession } from "../../src/verifier/verifier.js";

// With the REAL engine and model: runs only when SECRETGATE_VERIFIER_ASSETS
// names a directory holding the four pinned files (`secretgate verifier
// fetch` writes them under ~/.secretgate/verifier/…). Skipped otherwise.
const source = process.env.SECRETGATE_VERIFIER_ASSETS;
const value = ["Qm7", "xR2", "pL9", "vN4", "kT8"].join("");

describe.skipIf(!source)("the verifier with its real assets", () => {
  let home: string;
  beforeAll(() => {
    home = mkdtempSync(join(tmpdir(), "secretgate-real-"));
    process.env.SECRETGATE_HOME = home;
    mkdirSync(assetDir(), { recursive: true });
    for (const a of ASSETS) copyFileSync(join(source!, a.file), join(assetDir(), a.file));
  });
  afterAll(() => {
    delete process.env.SECRETGATE_HOME;
    rmSync(home, { recursive: true, force: true });
  });

  it("finds every pinned file verified, and loads both builds with the thresholds of the model file", () => {
    expect(assetStates().map((s) => s.state)).toEqual(["verified", "verified", "verified", "verified"]);
    const baseline = loadEngine("f1", { force: "simd128" });
    expect(baseline.build).toBe("simd128");
    expect(baseline.tau).toBeCloseTo(0.2598, 4);
    expect(loadEngine("f05").tau).toBeCloseTo(0.4684, 4);
    expect(loadEngine("f2").tau).toBeCloseTo(0.0781, 4);
    // Node 21 and later validate relaxed SIMD.
    if (Number(process.versions.node.split(".")[0]) >= 21) expect(loadEngine("f1").build).toBe("relaxed-simd");
  });

  it("judges the same candidate the same way with both builds", () => {
    const [record] = candidateRecords(`DB_PASS=${value}w`, { reported: false });
    const a = loadEngine("f1").judge({ ...record! });
    const b = loadEngine("f1", { force: "simd128" }).judge({ ...record! });
    expect(Math.abs(a - b)).toBeLessThan(1e-5);
    expect(a).toBeGreaterThan(0.2598);
  });

  it("rejects a placeholder the rules' filters would have dropped", () => {
    const s = new VerifierSession({ config: { enabled: true, threshold: "f1" } });
    expect(s.accept('password = "changeme"\n', [])).toEqual([]);
    expect(s.stats.judged).toBe(1);
  });

  it("redacts what the rules miss in a real hook event", async () => {
    writeFileSync(join(home, "config.json"), JSON.stringify({ verifier: { enabled: true } }));
    const r = await handleClaudeCode(
      "post-tool-use",
      JSON.stringify({
        session_id: "s1",
        cwd: "/tmp",
        tool_name: "Bash",
        tool_input: { command: "env" },
        tool_response: { stdout: `DB_PASS=${value}\n`, stderr: "" },
      }),
    );
    expect(r.stdout).not.toContain(value);
    expect(JSON.parse(r.stdout).hookSpecificOutput.updatedToolOutput.stdout).toMatch(/^DB_PASS=SECRETGATE_[0-9a-f]{12}\n$/);
    expect(new Vault().list().map((e) => e.ruleId)).toEqual([VERIFIER_RULE_ID]);
  });

  it("loads through a symlinked asset (its bytes are what is checked)", () => {
    const moved = join(home, "gguf-elsewhere");
    renameSync(join(assetDir(), "s6-secrets-verify-pico.gguf"), moved);
    symlinkSync(moved, join(assetDir(), "s6-secrets-verify-pico.gguf"));
    try {
      expect(loadEngine("f1").tau).toBeCloseTo(0.2598, 4);
    } finally {
      rmSync(join(assetDir(), "s6-secrets-verify-pico.gguf"));
      renameSync(moved, join(assetDir(), "s6-secrets-verify-pico.gguf"));
    }
  });

  it("concurrent hooks of the built bundle share the asset directory and all redact the same", async () => {
    const bundle = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "scripts", "secretgate.mjs");
    const input = JSON.stringify({
      session_id: "s1",
      cwd: "/tmp",
      tool_name: "Bash",
      tool_input: { command: "env" },
      tool_response: { stdout: `DB_PASS=${value}\n`, stderr: "" },
    });
    const runs = await Promise.all(
      Array.from(
        { length: 8 },
        () =>
          new Promise<string>((done, fail) => {
            const child = spawn(process.execPath, [bundle, "hook", "claude-code", "post-tool-use"], { env: { ...process.env, SECRETGATE_HOME: home } });
            let out = "";
            child.stdout.on("data", (d) => {
              out += d;
            });
            child.on("error", fail);
            child.on("close", () => done(out));
            child.stdin.end(input);
          }),
      ),
    );
    const outputs = runs.map((r) => JSON.parse(r).hookSpecificOutput.updatedToolOutput.stdout);
    expect(new Set(outputs).size).toBe(1);
    expect(outputs[0]).toMatch(/^DB_PASS=SECRETGATE_[0-9a-f]{12}\n$/);
  }, 60_000);
});
