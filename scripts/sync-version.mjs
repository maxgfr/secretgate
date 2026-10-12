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

// Each file must end up carrying the version. A pattern that matched nothing
// (the file was reshaped) fails the release instead of shipping a stale copy,
// and nothing is written until every file is known to be right.
const pending = [];
function edit(path, transform, read) {
  const before = readFileSync(path, "utf8");
  const after = transform(before);
  if (read(after) !== version) {
    console.error(`sync-version: could not set ${version} in ${path} — its version line was not found; nothing was changed`);
    process.exit(1);
  }
  if (after !== before) pending.push([path, after]);
}

// Only the YAML frontmatter of SKILL.md, never a `version:` in its body.
function inFrontmatter(text, fn) {
  const m = /^(---\r?\n)([\s\S]*?)(\r?\n---(?:\r?\n|$))/.exec(text);
  return m ? m[1] + fn(m[2]) + m[3] + text.slice(m[0].length) : text;
}
const frontmatterVersion = (text) => /^---\r?\n[\s\S]*?^[ \t]+version:[ \t]*(\S+)[ \t]*$[\s\S]*?^---/m.exec(text)?.[1];

edit(
  "package.json",
  (s) => s.replace(/("version":\s*")[^"]+(")/, `$1${version}$2`),
  (s) => JSON.parse(s).version,
);
edit(
  "src/version.ts",
  (s) => s.replace(/(export const VERSION = ")[^"]+(";)/, `$1${version}$2`),
  (s) => /export const VERSION = "([^"]+)";/.exec(s)?.[1],
);
edit(
  "skills/secretgate/SKILL.md",
  (s) => inFrontmatter(s, (fm) => fm.replace(/^([ \t]+version:[ \t]*)\S+[ \t]*$/m, `$1${version}`)),
  frontmatterVersion,
);

for (const [path, text] of pending) writeFileSync(path, text);
console.log(`sync-version: set ${version} in package.json, src/version.ts, skills/secretgate/SKILL.md`);
