import { describe, expect, it } from "vitest";
import { run } from "../src/cli.js";
import { VERSION } from "../src/version.js";

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
    for (const cmd of ["install", "uninstall", "status", "scan", "pipe", "allow", "vault", "hook"]) {
      expect(help).toContain(cmd);
    }
  });
});
