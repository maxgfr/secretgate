#!/usr/bin/env node
// Refresh rules/gitleaks.toml from upstream at the latest commit touching it,
// update the pin file, regenerate src/engine/rules.gen.ts and print the rule
// diff. Dev-time only (network).
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

async function fetchJson(url) {
  const res = await fetch(url, { headers: { "user-agent": "secretgate-sync-rules" } });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.json();
}

const commits = await fetchJson("https://api.github.com/repos/gitleaks/gitleaks/commits?path=config/gitleaks.toml&per_page=1");
const sha = commits[0].sha;
const rawUrl = `https://raw.githubusercontent.com/gitleaks/gitleaks/${sha}/config/gitleaks.toml`;
const res = await fetch(rawUrl);
if (!res.ok) throw new Error(`${rawUrl}: HTTP ${res.status}`);
const toml = await res.text();

const tomlPath = join(root, "rules", "gitleaks.toml");
const before = readFileSync(tomlPath, "utf8");
const beforeIds = new Set([...before.matchAll(/^id = "([^"]+)"/gm)].map((m) => m[1]));
const afterIds = new Set([...toml.matchAll(/^id = "([^"]+)"/gm)].map((m) => m[1]));

writeFileSync(tomlPath, toml);
writeFileSync(
  join(root, "rules", "UPSTREAM"),
  [
    `source: ${rawUrl}`,
    `commit: ${sha}`,
    "license: MIT (gitleaks, https://github.com/gitleaks/gitleaks/blob/master/LICENSE)",
    `fetched: ${new Date().toISOString().slice(0, 10)}`,
    "refresh: pnpm run rules:sync",
    "",
  ].join("\n"),
);

const added = [...afterIds].filter((id) => !beforeIds.has(id));
const removed = [...beforeIds].filter((id) => !afterIds.has(id));
console.log(`sync-rules: pinned ${sha}`);
console.log(`sync-rules: +${added.length} rule(s) ${added.join(", ") || "-"}`);
console.log(`sync-rules: -${removed.length} rule(s) ${removed.join(", ") || "-"}`);

execFileSync("node", [join(root, "scripts", "convert-rules.mjs")], { stdio: "inherit" });
console.log("sync-rules: done — review the diff, run the tests (incl. differential) before committing.");
