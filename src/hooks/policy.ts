import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import type { SecretgateConfig } from "../config.js";
import { canonical, covers, expandHome, sensitivePathMatch, commandTouchesSensitivePath } from "../paths.js";
import { isSecretgateState, toolCallScopeViolation } from "../scope.js";
import { analyzeShell } from "../shell-paths.js";
import type { NormalizedToolCall } from "./tool-call.js";

// What happens to a tool call BEFORE it runs, for every host. Order matters:
//   1. an unusable .secretgate.json fails closed (it may have held a scope);
//   2. the project scope (stays on while secretgate is disabled — a pause
//      switches off secret scanning, not the boundary the repository declared);
//   3. tamper guard: switching secretgate off or rewriting its wiring is the
//      user's call, so the host asks (or refuses, where it cannot ask);
//   4. sensitive-path deny (.env, keys…).
// Placeholder restore runs after this, in the host adapter.

export interface PreDecision {
  action: "deny" | "ask";
  reason: string;
}

function touchesOnly(call: NormalizedToolCall, file: string, cwd: string): boolean {
  if (call.kind !== "read" && call.kind !== "write" && call.kind !== "patch") return false;
  return call.paths.length > 0 && call.paths.every((p) => canonical(resolve(cwd, expandHome(p))) === canonical(file));
}

// Files whose edit would switch secretgate off or unwire it.
function guardedPath(abs: string, cwd: string): boolean {
  const home = homedir();
  const name = basename(abs).toLowerCase();
  if (name === ".secretgate.json") return true;
  if (basename(dirname(abs)).toLowerCase() === ".claude" && /^settings(?:\.[\w-]+)?\.json$/.test(name)) return true;
  const codex = process.env.CODEX_HOME ?? join(home, ".codex");
  const opencode = join(process.env.XDG_CONFIG_HOME ?? join(home, ".config"), "opencode");
  return (
    isSecretgateState(abs) ||
    covers(join(codex, "hooks.json"), abs) ||
    covers(join(codex, "config.toml"), abs) ||
    covers(join(opencode, "plugin"), abs) ||
    covers(join(opencode, "opencode.json"), abs) ||
    (name === "opencode.json" && covers(cwd, abs))
  );
}

// `secretgate disable`, `node …/secretgate.mjs allow --rule x`, …
const SELF_DISABLE = /(?:^|[\s;&|(/"'`])secretgate(?:\.mjs)?["']?\s+(disable|allow|uninstall|trust|vault\s+clear)\b/;

function tamperReason(call: NormalizedToolCall, cwd: string): string | undefined {
  if (call.kind === "shell" && call.command !== undefined) {
    const text = Array.isArray(call.command) ? call.command.join(" ") : call.command;
    const m = SELF_DISABLE.exec(text);
    if (m) return `this runs \`secretgate ${m[1]}\`, which changes what secretgate protects — that is your call, not the agent's`;
    const base = call.workdir ? resolve(cwd, expandHome(call.workdir)) : cwd;
    for (const ref of analyzeShell(call.command, { cwd: base }).refs) {
      if (ref.kind === "write" && guardedPath(canonical(ref.path), cwd)) return `this command writes '${ref.raw}', which configures secretgate or its hooks`;
    }
    return undefined;
  }
  if (call.kind === "write" || call.kind === "patch") {
    for (const p of call.paths)
      if (guardedPath(canonical(resolve(cwd, expandHome(p))), cwd)) return `this edits '${p}', which configures secretgate or its hooks`;
  }
  return undefined;
}

// A search pattern that names sensitive files (`Grep {glob: ".env*"}`).
function patternLooksSensitive(pattern: string, allowlist: SecretgateConfig["allowlist"], cwd: string): string | undefined {
  const name = basename(pattern);
  for (const probe of [name.replace(/[*?]/g, ""), name.replace(/[*?]/g, "x")]) {
    if (probe && sensitivePathMatch(probe, allowlist, cwd)) return pattern;
  }
  return undefined;
}

function sensitiveReason(call: NormalizedToolCall, cfg: SecretgateConfig, cwd: string): string | undefined {
  const deny = (target: string, hit: string): string =>
    `secretgate: '${target}' looks sensitive (${hit}); its content must not enter the model. If the agent needs a value from it, reference it as an env var instead — or allow the file with \`secretgate allow --path '${target}'\`.`;
  switch (call.kind) {
    case "read":
    case "other":
      for (const p of call.paths) {
        const hit = sensitivePathMatch(p, cfg.allowlist, cwd);
        if (hit) return deny(p, hit);
      }
      return undefined;
    case "search": {
      for (const p of call.paths) {
        // A directory like ~/.ssh: anything inside it matches `**/.ssh/**`.
        const hit = sensitivePathMatch(p, cfg.allowlist, cwd) ?? sensitivePathMatch(join(p, "x"), cfg.allowlist, cwd);
        if (hit) return deny(p, hit);
      }
      const pattern = call.pattern ? patternLooksSensitive(call.pattern, cfg.allowlist, cwd) : undefined;
      return pattern ? deny(pattern, "search pattern naming sensitive files") : undefined;
    }
    case "shell": {
      if (call.command === undefined) return undefined;
      const base = call.workdir ? resolve(cwd, expandHome(call.workdir)) : cwd;
      const touched = commandTouchesSensitivePath(call.command, cfg.allowlist, base);
      return touched ? `secretgate: this command reads '${touched}', which looks sensitive. Its content must not enter the model.` : undefined;
    }
    default:
      return undefined;
  }
}

export function preToolPolicy(call: NormalizedToolCall, cfg: SecretgateConfig, cwd: string, opts: { disabled: boolean }): PreDecision | undefined {
  if (cfg.error && !touchesOnly(call, cfg.error.file, cwd)) {
    return {
      action: "deny",
      reason: `secretgate: ${cfg.error.file} is invalid (${cfg.error.message}). Tool calls are refused until it is fixed, because it may declare a scope. Fix the file (the agent may read and edit it).`,
    };
  }
  const scope = toolCallScopeViolation(cfg.scopes, call, cwd);
  if (scope) return { action: "deny", reason: scope };
  if (opts.disabled) return undefined;
  const tamper = tamperReason(call, cwd);
  if (tamper) return { action: "ask", reason: `secretgate: ${tamper}. Approve only if you asked for it.` };
  const sensitive = sensitiveReason(call, cfg, cwd);
  if (sensitive) return { action: "deny", reason: sensitive };
  return undefined;
}
