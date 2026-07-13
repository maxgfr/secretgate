#!/usr/bin/env node
// Mirror the CLI bundle (scripts/secretgate.mjs, produced by tsup) byte-for-byte
// into the skill package. Skills ship standalone — `npx skills add` copies one
// skill directory (skills/secretgate/), so the engine has to live next to the
// SKILL.md. `check:build` asserts the copies never drift from the tested bundle.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const source = join(root, "scripts", "secretgate.mjs");
const targets = [join(root, "skills", "secretgate", "scripts", "secretgate.mjs")];

const bundle = readFileSync(source, "utf8");
for (const target of targets) {
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, bundle);
  console.log(`copy-bundle: ${source} -> ${target}`);
}
