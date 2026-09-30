import { basename, resolve } from "node:path";
import type { SecretgateConfig } from "../config.js";
import { canonical, commandTouchesSensitivePath, expandHome, sensitivePathMatch } from "../paths.js";
import { isPolicyFile, mayModify, toolCallScopeViolation } from "../scope.js";
import { analyzeShell, secretgateInvocation } from "../shell-paths.js";
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

// Subcommands that change what secretgate protects.
const GUARDED = new Set(["disable", "allow", "uninstall", "trust", "vault clear"]);

function tamperReason(call: NormalizedToolCall, cwd: string): string | undefined {
  if (call.kind === "shell" && call.command !== undefined) {
    const base = call.workdir ? resolve(cwd, expandHome(call.workdir)) : cwd;
    const analysis = analyzeShell(call.command, { cwd: base });
    // Judged on argv after quote removal: `secretgate 'disable'` is caught,
    // `git commit -m "document secretgate disable"` is not a disable.
    for (const argv of analysis.commands) {
      const verb = secretgateInvocation(argv);
      if (verb && GUARDED.has(verb.replace(/^\?/, ""))) {
        return verb.startsWith("?")
          ? `this runs a program named by a variable with \`${verb.slice(1)}\` — it may be secretgate, and changing what secretgate protects is your call, not the agent's`
          : `this runs \`secretgate ${verb}\`, which changes what secretgate protects — that is your call, not the agent's`;
      }
    }
    for (const ref of analysis.refs) {
      if (ref.kind !== "list" && mayModify(ref) && isPolicyFile(canonical(ref.path), cwd))
        return `this command may change '${ref.raw}', which configures secretgate or its hooks`;
    }
    return undefined;
  }
  if (call.kind === "write" || call.kind === "patch") {
    for (const p of call.paths)
      if (isPolicyFile(canonical(resolve(cwd, expandHome(p))), cwd)) return `this edits '${p}', which configures secretgate or its hooks`;
  }
  return undefined;
}

// A search pattern that names sensitive files (`Grep {glob: ".env*"}`).
// Probed inside the searched directory, so a fixtures tree stays searchable.
function patternLooksSensitive(pattern: string, root: string, allowlist: SecretgateConfig["allowlist"], cwd: string): string | undefined {
  const name = basename(pattern);
  for (const probe of [name.replace(/[*?]/g, ""), name.replace(/[*?]/g, "x")]) {
    if (probe && sensitivePathMatch(resolve(cwd, expandHome(root), probe), allowlist, cwd)) return pattern;
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
      // Glob lists names; only a content search (Grep) can print a file.
      if (!call.content) return undefined;
      for (const p of call.paths) {
        // A sensitive directory itself counts: `**/.ssh/**` matches `~/.ssh`.
        const hit = sensitivePathMatch(p, cfg.allowlist, cwd);
        if (hit) return deny(p, hit);
      }
      const pattern = call.pattern ? patternLooksSensitive(call.pattern, call.searchRoot ?? ".", cfg.allowlist, cwd) : undefined;
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
      reason: `secretgate: ${cfg.error.file} is invalid (${cfg.error.message}). Tool calls are refused until it is fixed, because it may declare a scope. Fix it yourself, or let the agent edit it (you will be asked to approve).`,
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
