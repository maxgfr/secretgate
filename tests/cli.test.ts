import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { run } from "../src/cli.js";
import { VERSION } from "../src/version.js";
import { FAKE } from "./fixtures/fake-tokens.js";

function capture() {
  const out: string[] = [];
  const err: string[] = [];
  return {
    io: { stdout: (s: string) => out.push(s), stderr: (s: string) => err.push(s) },
    out,
    err,
  };
}

describe("cli router", () => {
  it("--version prints the version and exits 0", async () => {
    const { io, out } = capture();
    const code = await run(["--version"], io);
    expect(code).toBe(0);
    expect(out.join("")).toContain(VERSION);
  });

  it("no arguments prints usage and exits 2", async () => {
    const { io, err } = capture();
    const code = await run([], io);
    expect(code).toBe(2);
    expect(err.join("")).toContain("Usage");
  });

  it("an unknown command prints usage and exits 2", async () => {
    const { io, err } = capture();
    const code = await run(["frobnicate"], io);
    expect(code).toBe(2);
    expect(err.join("")).toContain("Unknown command");
  });

  it("--help lists every public command", async () => {
    const { io, out } = capture();
    const code = await run(["--help"], io);
    expect(code).toBe(0);
    const help = out.join("");
    for (const cmd of ["install", "uninstall", "status", "scan", "pipe", "allow", "vault", "disable", "enable", "hook"]) {
      expect(help).toContain(cmd);
    }
  });
});

describe("scan — gitleaks hybrid findings", () => {
  it("are placed at the line gitleaks reports, in file order", async () => {
    const dir = mkdtempSync(join(tmpdir(), "sg-hybrid-"));
    const bin = join(dir, "bin");
    const repo = join(dir, "repo");
    const savedPath = process.env.PATH;
    const savedCwd = process.cwd();
    try {
      for (const d of [bin, repo]) mkdirSync(d, { recursive: true });
      // A stub gitleaks: a file holding `extra-value-1` gets one finding, on line 3.
      writeFileSync(
        join(bin, "gitleaks"),
        `#!/bin/sh\ninput=$(cat)\ncase "$input" in *extra-value-1*) echo '[{"RuleID":"stub","Secret":"extra-value-1","StartLine":3}]' > "$8"; exit 99;; esac\necho '[]' > "$8"\nexit 0\n`,
      );
      chmodSync(join(bin, "gitleaks"), 0o755);
      writeFileSync(join(repo, "a.txt"), `token ${FAKE.githubPat}\nextra-value-1\nextra-value-1 again\n`);
      writeFileSync(join(repo, "b.txt"), `token ${FAKE.githubPat}\n`);
      process.env.PATH = `${bin}:${savedPath}`;
      process.chdir(repo);
      vi.resetModules();
      const { run: freshRun } = await import("../src/cli.js");
      const { io, out } = capture();
      await freshRun(["scan", ".", "--json"], io);
      const findings = JSON.parse(out.join("")).findings as Array<{ path: string; line: number; ruleId: string }>;
      expect(findings.map((f) => `${f.path}:${f.line}`)).toEqual(["a.txt:1", "a.txt:3", "b.txt:1"]);
      expect(findings[1]!.ruleId).toBe("gitleaks:stub");
    } finally {
      process.env.PATH = savedPath;
      process.chdir(savedCwd);
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
