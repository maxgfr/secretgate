#!/usr/bin/env node
// Portable, install-free check of the shipped bundles, including Node 18/Windows.
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
const temp = mkdtempSync(join(tmpdir(), "secretgate-runtime-"));
try {
  const bundle = resolve("skills/secretgate/scripts/secretgate.mjs");
  const env = {
    ...process.env,
    HOME: temp,
    USERPROFILE: temp,
    CODEX_HOME: join(temp, ".codex"),
    SECRETGATE_HOME: join(temp, ".secretgate"),
    XDG_CONFIG_HOME: join(temp, ".config"),
    SECRETGATE_DISABLE: "0",
  };
  const fake = "ghp_" + ["aB3dE6", "gH9jK2", "mN5pQ8", "sT1vW4", "yZ7bC0", "dF6hJ9"].join("");
  const scanned = spawnSync(process.execPath, [bundle, "scan", "-", "--json"], { env, input: fake, encoding: "utf8" });
  assert.equal(scanned.status, 1);
  assert(!scanned.stdout.includes(fake));
  const output = execFileSync(process.execPath, [bundle, "init", "--all"], { env, cwd: temp, encoding: "utf8" });
  assert(output.includes("local checks passed"));
  const plugin = await import(pathToFileURL(resolve("skills/secretgate/scripts/secretgate-opencode.mjs")));
  assert.equal(typeof plugin.SecretgatePlugin, "function");
  execFileSync(process.execPath, [bundle, "uninstall", "--all"], { env, cwd: temp, stdio: "pipe" });
  console.log(`PASS install-free runtime ${process.platform} ${process.version}: scan, three installers, adapter checks, uninstall`);
} finally {
  rmSync(temp, { recursive: true, force: true });
}
