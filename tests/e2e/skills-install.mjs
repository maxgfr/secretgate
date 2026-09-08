#!/usr/bin/env node
// Exercise the actual skills distribution path separately for every agent.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
const source = resolve(".");
const agents = process.argv.slice(2).length ? process.argv.slice(2) : ["claude-code", "codex", "opencode"];
for (const agent of agents) {
  assert(["claude-code", "codex", "opencode"].includes(agent));
  const temp = mkdtempSync(join(tmpdir(), "secretgate-distribution-"));
  try {
    execFileSync("npx", ["--yes", "skills", "add", source, "--skill", "secretgate", "--agent", agent, "--copy", "-y"], { cwd: temp, stdio: "pipe" });
    const dirs = [".agents", ".claude", ".codex", ".opencode"];
    const bundle = dirs.map((dir) => join(temp, dir, "skills/secretgate/scripts/secretgate.mjs")).find(existsSync);
    assert(bundle, `${agent}: installed skill lost its bundle`);
    const env = {
      ...process.env,
      HOME: temp,
      USERPROFILE: temp,
      CODEX_HOME: join(temp, ".codex"),
      SECRETGATE_HOME: join(temp, ".secretgate"),
      XDG_CONFIG_HOME: join(temp, ".config"),
      SECRETGATE_DISABLE: "0",
    };
    const output = execFileSync(process.execPath, [bundle, "init", "--" + agent], { cwd: temp, env, encoding: "utf8" });
    assert(output.includes("local checks passed"));
    console.log(`PASS skills add -> ${agent} -> installed adapter checks`);
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
}
