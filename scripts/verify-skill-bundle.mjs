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

// Both the CLI and the OpenCode plugin bundle must ship in the skill dir, and
// be byte-identical to the tested root bundles. `install --opencode` copies the
// plugin from beside the CLI, so a missing plugin bundle breaks `init` on any
// machine that has OpenCode.
for (const name of ["secretgate.mjs", "secretgate-opencode.mjs"]) {
  const rootBundle = join(root, "scripts", name);
  const skillBundle = join(skillDir, "scripts", name);
  if (!existsSync(rootBundle)) bad(`missing scripts/${name} — run \`pnpm run build\``);
  else if (!existsSync(skillBundle)) bad(`missing skills/secretgate/scripts/${name} — run \`pnpm run build\``);
  else if (readFileSync(rootBundle, "utf8") !== readFileSync(skillBundle, "utf8")) bad(`skill ${name} differs from scripts/${name} — run \`pnpm run build\``);
  else ok(`skill ${name} is byte-identical to the tested bundle`);
}

// One version everywhere: what `--version` prints, what the skill declares and
// what the package is released as. sync-version.mjs keeps them in lockstep.
const versions = {
  "package.json": JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version,
  "src/version.ts": /export const VERSION = "([^"]+)";/.exec(readFileSync(join(root, "src", "version.ts"), "utf8"))?.[1],
  "SKILL.md metadata.version": existsSync(skillMd)
    ? /^---\r?\n[\s\S]*?^[ \t]+version:[ \t]*(\S+)[ \t]*$[\s\S]*?^---/m.exec(readFileSync(skillMd, "utf8"))?.[1]
    : undefined,
};
new Set(Object.values(versions)).size === 1 && versions["package.json"]
  ? ok(`version ${versions["package.json"]} in package.json, src/version.ts and SKILL.md`)
  : bad(`versions disagree: ${Object.entries(versions)
      .map(([k, v]) => `${k}=${v ?? "missing"}`)
      .join(", ")} — run \`node scripts/sync-version.mjs <version>\``);

if (errors.length > 0) {
  console.error(`verify-skill-bundle: ${errors.length} problem(s)`);
  process.exit(1);
}
console.log("verify-skill-bundle: all good");
