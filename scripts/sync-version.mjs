#!/usr/bin/env node
// Sync the release version across every place it lives, then let the caller
// rebuild the bundles. Invoked by @semantic-release/exec (prepareCmd):
//   node scripts/sync-version.mjs <version>
import { readFileSync, writeFileSync } from "node:fs";

const version = process.argv[2];
if (!version || !/^\d+\.\d+\.\d+(?:-[\w.]+)?$/.test(version)) {
  console.error(`sync-version: expected a semver version, got "${version ?? ""}"`);
  process.exit(1);
}

function edit(path, transform) {
  const before = readFileSync(path, "utf8");
  const after = transform(before);
  if (after === before) {
    console.error(`sync-version: WARNING — no change applied to ${path}`);
  }
  writeFileSync(path, after);
}

edit("package.json", (s) => s.replace(/("version":\s*")[^"]+(")/, `$1${version}$2`));
edit("src/version.ts", (s) => s.replace(/(export const VERSION = ")[^"]+(";)/, `$1${version}$2`));
edit("skills/secretgate/SKILL.md", (s) => s.replace(/(\n[ \t]+version:[ \t]*)[^\n]+/, `$1${version}`));

console.log(`sync-version: set ${version} in package.json, src/version.ts, skills/secretgate/SKILL.md`);
