#!/usr/bin/env node
// Dev-time converter: rules/gitleaks.toml (Go/RE2 regexes) -> src/engine/rules.gen.ts
// (JS-compatible regexes, compiled and validated). Run via `pnpm run rules:convert`;
// `--check` regenerates in memory and fails if the committed file is stale
// (wired into `check:build`).
//
// Go/RE2 constructs that JS (Node 18 floor — no ES2025 regex modifiers) lacks:
//   (?i) leading         -> hoisted to the `i` flag (exact)
//   (?i) mid-pattern     -> hoisted to the `i` flag (LOOSENED: prefix becomes
//                           case-insensitive too — over-matching is acceptable
//                           for a firewall, recall beats precision)
//   (?i:...) group       -> (?:...) + hoisted `i` flag (LOOSENED)
//   (?-i:...) group      -> (?:...) (LOOSENED: stays case-insensitive)
//   (?s:...) group       -> dots inside rewritten to [\s\S] (EXACT)
//   (?P<name>...)        -> (?<name>...) (exact)
// Anything else that fails to compile must get a MANUAL_OVERRIDES entry —
// rules are NEVER silently dropped (the test suite asserts dropped === []).
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parse as parseToml } from "smol-toml";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const TOML_PATH = join(root, "rules", "gitleaks.toml");
const OUT_PATH = join(root, "src", "engine", "rules.gen.ts");

// ruleId -> { source, flags } for patterns the automatic transform cannot handle.
const MANUAL_OVERRIDES = {};

export function convertGoRegex(goSource) {
  const loosened = [];
  const flags = new Set();
  let src = goSource.replace(/\(\?P</g, "(?<");

  // Leading inline flag runs: (?i), (?is), (?i)(?s), ...
  let lead;
  while ((lead = /^\(\?([a-z]+)\)/.exec(src))) {
    for (const f of lead[1]) flags.add(f);
    src = src.slice(lead[0].length);
  }

  let out = "";
  let i = 0;
  let inClass = false;
  // Stack of open groups; each entry records whether dot-rewrite (dotall) is
  // active inside it. Inherited by nested groups.
  const stack = [];
  const dotall = () => stack.length > 0 && stack[stack.length - 1].dotall;

  while (i < src.length) {
    const c = src[i];
    if (c === "\\") {
      out += src.slice(i, i + 2);
      i += 2;
      continue;
    }
    if (inClass) {
      if (c === "]") inClass = false;
      out += c;
      i++;
      continue;
    }
    if (c === "[") {
      inClass = true;
      out += c;
      i++;
      continue;
    }
    if (c === "." && dotall()) {
      out += "[\\s\\S]";
      i++;
      continue;
    }
    if (c === ")") {
      stack.pop();
      out += c;
      i++;
      continue;
    }
    if (c === "(") {
      const rest = src.slice(i);
      // Standard constructs pass through: (?:  (?=  (?!  (?<=  (?<!  (?<name>
      const std = /^\(\?(?::|=|!|<[=!]|<[a-zA-Z_][a-zA-Z0-9_]*>)/.exec(rest);
      if (std) {
        stack.push({ dotall: dotall() });
        out += std[0];
        i += std[0].length;
        continue;
      }
      // Inline flag constructs: (?flags) or (?flags:
      const fl = /^\(\?([a-z]*(?:-[a-z]+)?)([):])/.exec(rest);
      if (fl && fl[1] !== "") {
        const [enabledPart, disabledPart = ""] = fl[1].split("-");
        const isGroup = fl[2] === ":";
        let groupDotall = dotall();
        for (const f of enabledPart) {
          if (f === "s") {
            if (isGroup) groupDotall = true;
            else {
              flags.add("s");
              loosened.push(`mid-pattern (?s) hoisted in ${goSource}`);
            }
          } else {
            flags.add(f);
            loosened.push(`${isGroup ? `(?${fl[1]}:)` : `(?${fl[1]})`} hoisted '${f}' in ${goSource}`);
          }
        }
        for (const f of disabledPart) {
          if (f === "s") {
            if (isGroup) groupDotall = false;
          } else {
            loosened.push(`(?-${f}:) dropped (stays '${f}'-flagged) in ${goSource}`);
          }
        }
        if (isGroup) {
          stack.push({ dotall: groupDotall });
          out += "(?:";
        }
        i += fl[0].length;
        continue;
      }
      // Plain capturing group
      stack.push({ dotall: dotall() });
      out += c;
      i++;
      continue;
    }
    out += c;
    i++;
  }

  // Go's \x60 (backtick) is valid JS; \A and \z are not used by the vendored
  // config (asserted below) but map them defensively as whole tokens.
  out = out.replace(/\\A/g, "^").replace(/\\z/g, "$");

  return { source: out, flags: [...flags].sort().join(""), loosened };
}

function convertAllowlistEntry(entry, dropped, ruleId) {
  const converted = {};
  if (entry.condition) converted.condition = String(entry.condition).toUpperCase();
  if (entry.regexTarget) converted.regexTarget = entry.regexTarget;
  if (entry.regexes) {
    converted.regexes = entry.regexes.map((r) => {
      const c = convertGoRegex(String(r));
      try {
        new RegExp(c.source, c.flags);
      } catch (e) {
        dropped.push(`${ruleId} allowlist regex: ${e.message}`);
      }
      return { source: c.source, flags: c.flags };
    });
  }
  if (entry.stopwords) converted.stopwords = entry.stopwords.map((s) => String(s).toLowerCase());
  if (entry.paths) {
    converted.paths = entry.paths.map((p) => {
      const c = convertGoRegex(String(p));
      return { source: c.source, flags: c.flags };
    });
  }
  return converted;
}

export async function convertConfig() {
  const toml = parseToml(readFileSync(TOML_PATH, "utf8"));
  const rules = [];
  const dropped = [];
  const loosened = [];

  for (const raw of toml.rules ?? []) {
    const id = raw.id;
    let regex;
    if (MANUAL_OVERRIDES[id]) {
      regex = MANUAL_OVERRIDES[id];
    } else {
      const c = convertGoRegex(String(raw.regex));
      regex = { source: c.source, flags: c.flags };
      loosened.push(...c.loosened.map((l) => `${id}: ${l}`));
    }
    try {
      new RegExp(regex.source, regex.flags + "dg");
      if (/\(\?[a-zA-Z-]*[isU][a-zA-Z-]*[):]/.test(regex.source)) {
        throw new Error("leftover inline flag construct");
      }
    } catch (e) {
      dropped.push(`${id}: ${e.message}`);
      continue;
    }
    const rule = { id, regex, keywords: (raw.keywords ?? []).map((k) => String(k).toLowerCase()) };
    if (typeof raw.entropy === "number") rule.entropy = raw.entropy;
    if (typeof raw.secretGroup === "number") rule.secretGroup = raw.secretGroup;
    const allowlists = raw.allowlists ?? (raw.allowlist ? [raw.allowlist] : []);
    if (allowlists.length > 0) {
      rule.allowlists = allowlists.map((a) => convertAllowlistEntry(a, dropped, id));
    }
    rules.push(rule);
  }

  const ga = toml.allowlist ?? {};
  const globalAllowlist = {
    paths: (ga.paths ?? []).map((p) => convertGoRegex(String(p)).source),
    regexes: (ga.regexes ?? []).map((r) => {
      const c = convertGoRegex(String(r));
      return { source: c.source, flags: c.flags };
    }),
    stopwords: (ga.stopwords ?? []).map((s) => String(s).toLowerCase()),
  };
  for (const p of globalAllowlist.paths) new RegExp(p);

  return { rules, dropped, loosened, globalAllowlist };
}

function render({ rules, globalAllowlist }) {
  return `// GENERATED by scripts/convert-rules.mjs from rules/gitleaks.toml — DO NOT EDIT.
// Regenerate with \`pnpm run rules:convert\`; upstream pin in rules/UPSTREAM.
export interface GenRegex {
  source: string;
  flags: string;
}

export interface GenAllowlist {
  condition?: "AND" | "OR";
  regexTarget?: "match" | "line";
  regexes?: GenRegex[];
  stopwords?: string[];
  paths?: GenRegex[];
}

export interface GenRule {
  id: string;
  regex: GenRegex;
  entropy?: number;
  secretGroup?: number;
  keywords: string[];
  allowlists?: GenAllowlist[];
}

export const RULES: GenRule[] = ${JSON.stringify(rules, null, 2)};

export const GLOBAL_ALLOWLIST: { paths: string[]; regexes: GenRegex[]; stopwords: string[] } = ${JSON.stringify(globalAllowlist, null, 2)};
`;
}

async function main() {
  const check = process.argv.includes("--check");
  const converted = await convertConfig();
  if (converted.dropped.length > 0) {
    console.error(`convert-rules: ${converted.dropped.length} rule(s) failed to convert — add MANUAL_OVERRIDES:`);
    for (const d of converted.dropped) console.error(`  - ${d}`);
    process.exit(1);
  }
  const content = render(converted);
  if (check) {
    const existing = readFileSync(OUT_PATH, "utf8");
    if (existing !== content) {
      console.error("convert-rules: src/engine/rules.gen.ts is STALE — run `pnpm run rules:convert`");
      process.exit(1);
    }
    console.log(`convert-rules: up to date (${converted.rules.length} rules)`);
    return;
  }
  writeFileSync(OUT_PATH, content);
  console.log(`convert-rules: wrote ${converted.rules.length} rules to src/engine/rules.gen.ts (${converted.loosened.length} loosened conversions)`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
