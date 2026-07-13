#!/usr/bin/env node
// Install-bundle gate: prove the repo is shaped so that `npx skills add
// maxgfr/secretgate` installs a WORKING skill — engine bundled next to
// SKILL.md, not a lone markdown file.
//
// The `skills` CLI (skills.sh) early-returns the moment it sees a SKILL.md at
// the repository ROOT and installs that file ALONE. A skill is only bundled
// whole when its SKILL.md lives in a SUBDIRECTORY (skills/<name>/).
// Pure Node, no deps, no network.
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

// Claude Code matches skill descriptions at <=1024 chars; 1000 leaves margin.
const DESC_MAX = 1000;

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const errors = [];
const ok = (m) => console.log(`  ok   ${m}`);
const bad = (m) => {
  errors.push(m);
  console.log(`  FAIL ${m}`);
};

existsSync(join(root, "SKILL.md"))
  ? bad("a SKILL.md exists at the repo ROOT — `skills add` would install it alone, dropping the engine. Keep it under skills/secretgate/")
  : ok("no root SKILL.md");

const skillDir = join(root, "skills", "secretgate");
const skillMd = join(skillDir, "SKILL.md");
if (!existsSync(skillMd)) {
  bad("missing skills/secretgate/SKILL.md");
} else {
  ok("skills/secretgate/SKILL.md present");
  const frontmatter = readFileSync(skillMd, "utf8").split("---")[1] ?? "";
  const desc = /description:\s*"?([\s\S]*?)"?\n(?:license|metadata):/.exec(frontmatter)?.[1] ?? "";
  desc.length > DESC_MAX ? bad(`SKILL.md description is ${desc.length} chars (max ${DESC_MAX})`) : ok(`SKILL.md description ${desc.length} chars (<= ${DESC_MAX})`);
}

const rootBundle = join(root, "scripts", "secretgate.mjs");
const skillBundle = join(skillDir, "scripts", "secretgate.mjs");
if (!existsSync(rootBundle)) {
  bad("missing scripts/secretgate.mjs — run `pnpm run build`");
} else if (!existsSync(skillBundle)) {
  bad("missing skills/secretgate/scripts/secretgate.mjs — run `pnpm run build`");
} else {
  readFileSync(rootBundle, "utf8") === readFileSync(skillBundle, "utf8")
    ? ok("skill engine is byte-identical to the tested bundle")
    : bad("skill engine differs from scripts/secretgate.mjs — run `pnpm run build`");
}

if (errors.length > 0) {
  console.error(`verify-skill-bundle: ${errors.length} problem(s)`);
  process.exit(1);
}
console.log("verify-skill-bundle: all good");
