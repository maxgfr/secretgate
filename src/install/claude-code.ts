import { type EditReport, editJsonFile } from "./json-merge.js";
import { existsSync, readFileSync, rmSync } from "node:fs";

// Deny rules complement the hooks where tool hooks don't fire — notably @file
// mentions, which inline a file's content WITHOUT firing tool hooks. They are
// deliberately limited to places where a match is a REAL secret: local env
// files, credential files in the home directory, tool credential files. A
// deny rule cannot express exceptions, so project-wide extension globs
// (`**/*.pem`, `**/*.key`, `**/credentials.json`…) would also refuse the fake
// keys in test fixtures that security work has to read; those are left to
// the hook, which exempts fixtures and still redacts their content.
export const CC_DENY_RULES = [
  "Read(**/.env)",
  "Read(**/.env.local)",
  "Read(**/.env.*.local)",
  "Read(**/.envrc)",
  "Read(**/.dev.vars)",
  "Read(~/.aws/**)",
  "Read(**/.aws/**)",
  "Read(~/.ssh/**)",
  "Read(**/.ssh/**)",
  "Read(~/.kube/config)",
  "Read(**/.kube/config)",
  "Read(**/.netrc)",
  "Read(**/.npmrc)",
  "Read(**/.docker/config.json)",
  "Read(**/.git-credentials)",
  "Read(**/.pgpass)",
  "Read(**/.pypirc)",
  "Read(~/.secretgate/vault.json)",
];

// Rules older versions installed and `init` now removes (they blocked fixtures).
export const RETIRED_DENY_RULES = [
  "Read(**/*.pem)",
  "Read(**/*.key)",
  "Read(**/id_rsa*)",
  "Read(**/id_ed25519*)",
  "Read(**/id_ecdsa*)",
  "Read(**/credentials.json)",
  "Read(**/*.p12)",
  "Read(**/*.pfx)",
  "Read(**/*.tfstate)",
];

// Identifies OUR hook entries regardless of how the CLI is invoked
// (`secretgate hook claude-code …`, `node …/secretgate.mjs hook claude-code …`).
const MARKER = "hook claude-code";

// PostToolUse redaction is the linchpin control, so it fires on EVERY tool
// (matcher "*") — an allow-list would silently miss MCP tools, custom tools and
// any future tool, letting their output reach the model unredacted. The
// deep-walk handles whatever shape the result has. PreToolUse stays targeted:
// its deny/scope/restore logic applies to the file, search and shell tools
// named here, plus MCP tools (whose path arguments are checked too); any
// secret another tool pulls in is still redacted by PostToolUse.
export const PRE_TOOL_MATCHER = "Read|Grep|Glob|LS|Edit|Write|MultiEdit|NotebookEdit|NotebookRead|Bash|mcp__.*";

const EVENTS: Array<{ event: string; arg: string; matcher?: string }> = [
  { event: "UserPromptSubmit", arg: "user-prompt-submit" },
  { event: "PreToolUse", arg: "pre-tool-use", matcher: PRE_TOOL_MATCHER },
  { event: "PostToolUse", arg: "post-tool-use", matcher: "*" },
];

/** Is a settings file wired with the current PreToolUse matcher? */
export function claudeCodeMatcherCurrent(settings: Record<string, any> | undefined): boolean {
  const groups = settings?.hooks?.PreToolUse;
  if (!Array.isArray(groups)) return false;
  return groups.some((g: HookGroup) => g.matcher === PRE_TOOL_MATCHER && (g.hooks ?? []).some((h) => String(h.command ?? "").includes(MARKER)));
}

interface HookGroup {
  matcher?: string;
  hooks: Array<{ type: string; command: string; timeout?: number }>;
}

function withoutOurGroups(groups: HookGroup[] | undefined): HookGroup[] {
  if (!Array.isArray(groups)) return [];
  return groups.map((g) => ({ ...g, hooks: (g.hooks ?? []).filter((h) => !String(h.command ?? "").includes(MARKER)) })).filter((g) => g.hooks.length > 0);
}

export interface InstallOptions {
  settingsPath: string;
  /** how the agent should invoke the CLI, e.g. `node /home/u/.secretgate/bin/secretgate.mjs` */
  command: string;
}

export function installClaudeCode({ settingsPath, command }: InstallOptions): EditReport {
  const ownershipPath = `${settingsPath}.secretgate-ownership.json`;
  const previous = existsSync(ownershipPath) ? JSON.parse(readFileSync(ownershipPath, "utf8")) : {};
  const added: string[] = [];
  const report = editJsonFile(settingsPath, (s) => {
    s.hooks ??= {};
    for (const { event, arg, matcher } of EVENTS) {
      const kept = withoutOurGroups(s.hooks[event]);
      // 30s cap (seconds): a hung hook must not stall every tool call for the 600s default.
      const group: HookGroup = { hooks: [{ type: "command", command: `${command} hook claude-code ${arg}`, timeout: 30 }] };
      if (matcher) group.matcher = matcher;
      s.hooks[event] = [...kept, group];
    }
    s.permissions ??= {};
    // Rules an older secretgate added and no longer ships (e.g. `**/*.pem`,
    // which blocked test fixtures) are removed — only the ones it owns.
    const retired = new Set(((previous.deny ?? []) as string[]).filter((r) => !CC_DENY_RULES.includes(r)));
    const deny: string[] = (Array.isArray(s.permissions.deny) ? s.permissions.deny : []).filter((r: string) => !retired.has(r));
    added.push(...CC_DENY_RULES.filter((r) => !deny.includes(r)));
    s.permissions.deny = [...deny, ...added];
  });
  editJsonFile(ownershipPath, (state) => {
    state.deny = [...new Set([...(previous.deny ?? []), ...added])].filter((r) => CC_DENY_RULES.includes(r));
  });
  return report;
}

export function uninstallClaudeCode({ settingsPath }: { settingsPath: string }): EditReport {
  const ownershipPath = `${settingsPath}.secretgate-ownership.json`;
  const owned: string[] = existsSync(ownershipPath) ? (JSON.parse(readFileSync(ownershipPath, "utf8")).deny ?? []) : [];
  const report = editJsonFile(settingsPath, (s) => {
    if (s.hooks && typeof s.hooks === "object") {
      for (const { event } of EVENTS) {
        const kept = withoutOurGroups(s.hooks[event]);
        if (kept.length > 0) s.hooks[event] = kept;
        else delete s.hooks[event];
      }
    }
    if (Array.isArray(s.permissions?.deny)) {
      s.permissions.deny = s.permissions.deny.filter((r: string) => !owned.includes(r));
      if (s.permissions.deny.length === 0) delete s.permissions.deny;
      if (Object.keys(s.permissions).length === 0) delete s.permissions;
    }
  });
  if (existsSync(ownershipPath)) rmSync(ownershipPath);
  return report;
}
