#!/usr/bin/env node
// Mirror BOTH bundles (the CLI and the OpenCode plugin, produced by tsup)
// byte-for-byte into the skill package. Skills ship standalone — `npx skills
// add` copies one skill directory (skills/secretgate/), so every bundle the CLI
// might need at runtime has to live next to the SKILL.md. In particular
// `secretgate install --opencode` copies the plugin bundle from beside the CLI,
// so it MUST ship in the skill dir too. `check:build` asserts the copies never
// drift from the tested bundles.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const skillScripts = join(root, "skills", "secretgate", "scripts");
const bundles = ["secretgate.mjs", "secretgate-opencode.mjs"];

for (const name of bundles) {
  const source = join(root, "scripts", name);
  const target = join(skillScripts, name);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, readFileSync(source, "utf8"));
  console.log(`copy-bundle: ${source} -> ${target}`);
}
