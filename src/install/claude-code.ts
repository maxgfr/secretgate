import { isSecretgateHook } from "./hook-marker.js";
import { assertWithin, type EditReport, editJsonFile } from "./json-merge.js";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { dirname } from "node:path";

// Deny rules complement the hooks where tool hooks don't fire — notably @file
// mentions, which inline a file's content WITHOUT firing tool hooks. They are
// deliberately limited to places where a match is a REAL secret: local env
// files, credential files in the home directory, tool credential files. A
// deny rule cannot express exceptions, so project-wide extension globs
// (`**/*.pem`, `**/*.key`, `**/credentials.json`…) would also refuse the fake
// keys in test fixtures that security work has to read. Those are left to the
// hooks, which exempt fixtures: the tool hooks for reads (content still
// redacted), the prompt hook for `@server.pem`-style mentions.
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

// Everything secretgate <= 1.4 installed, before it recorded ownership.
const LEGACY_DENY_RULES = [
  "Read(**/.env)",
  "Read(**/.env.local)",
  "Read(**/.env.*.local)",
  "Read(**/*.pem)",
  "Read(**/*.key)",
  "Read(**/id_rsa*)",
  "Read(**/id_ed25519*)",
  "Read(**/id_ecdsa*)",
  "Read(~/.aws/**)",
  "Read(**/.aws/**)",
  "Read(~/.ssh/**)",
  "Read(**/.ssh/**)",
  "Read(~/.kube/config)",
  "Read(**/.kube/config)",
  "Read(**/.netrc)",
  "Read(**/.npmrc)",
  "Read(**/.docker/config.json)",
  "Read(**/credentials.json)",
];

// The <= 1.4 rules secretgate still ships. An upgrade leaves them in place, so
// they never show up among the rules it adds.
const LEGACY_KEPT_RULES = LEGACY_DENY_RULES.filter((r) => CC_DENY_RULES.includes(r));

/**
 * Pre-ownership (<= 1.4) rules that are secretgate's although no record names
 * them: the complete legacy set when there is no record yet, or every legacy
 * rule still shipped — all present, none recorded — when an upgrade wrote a
 * record listing only the rules it added (secretgate 1.5 – 1.7.0).
 */
function unrecordedLegacyRules(deny: readonly unknown[], recorded: string[] | undefined): string[] {
  if (recorded === undefined) return LEGACY_DENY_RULES.every((r) => deny.includes(r)) ? LEGACY_DENY_RULES : [];
  return LEGACY_KEPT_RULES.every((r) => deny.includes(r) && !recorded.includes(r)) ? LEGACY_KEPT_RULES : [];
}

/**
 * Retired rules that are secretgate's to remove: recorded as installed by it,
 * or part of a complete pre-ownership (<= 1.4) rule set — all 18 of those
 * together can only come from secretgate. A lone rule the user wrote stays.
 */
export function retiredRulesToRemove(deny: string[], owned: string[]): string[] {
  const legacyInstall = LEGACY_DENY_RULES.every((r) => deny.includes(r));
  return RETIRED_DENY_RULES.filter((r) => deny.includes(r) && (owned.includes(r) || legacyInstall));
}

// Identifies OUR hook entries regardless of how the CLI is invoked
// (`secretgate hook claude-code …`, `node …/secretgate.mjs hook claude-code …`).

// PostToolUse redaction is the linchpin control, so it fires on EVERY tool
// (matcher "*") — an allow-list would silently miss MCP tools, custom tools and
// any future tool, letting their output reach the model unredacted. The
// deep-walk handles whatever shape the result has. PreToolUse stays targeted:
// its deny/scope/restore logic applies to the file, search and shell tools
// named here, plus MCP tools (whose path arguments are checked too); any
// secret another tool pulls in is still redacted by PostToolUse.
export const PRE_TOOL_MATCHER = "Read|Grep|Glob|LS|Edit|Write|MultiEdit|NotebookEdit|NotebookRead|Bash|mcp__.*";

//
// PostToolUse only fires for a call that SUCCEEDED. A failed one (a shell
// command that exits non-zero, an MCP error result) goes to PostToolUseFailure,
// which can neither replace the output nor stop the turn. PostToolBatch is the
// one hook that still stands between that output and the model: it receives
// every result of the batch as the model will read it, and can stop the turn.
//
// PostToolBatch is a recent event, and Claude Code before 2.1.101 ignores the
// WHOLE settings file when it names a hook event it does not know (its
// changelog for 2.1.101; seen on 2.0.0, where no hook ran and a pasted token
// went to the model). So that entry is written only for a Claude Code known
// to tolerate it; an older or unknown one keeps the three hooks it runs.
export const BATCH_HOOK_MIN_VERSION = "2.1.101";

/** Does this Claude Code (as `claude --version` prints it) take a settings
 *  file that names PostToolBatch? Unknown or unreadable: no. */
export function claudeCodeTakesBatchHook(version: string | undefined): boolean {
  const have = /(\d+)\.(\d+)\.(\d+)/.exec(version ?? "");
  if (!have) return false;
  const need = BATCH_HOOK_MIN_VERSION.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    const n = Number(have[i + 1]);
    if (n !== need[i]) return n > need[i]!;
  }
  return true;
}

const EVENTS: Array<{ event: string; arg: string; matcher?: string; recent?: boolean }> = [
  { event: "UserPromptSubmit", arg: "user-prompt-submit" },
  { event: "PreToolUse", arg: "pre-tool-use", matcher: PRE_TOOL_MATCHER },
  { event: "PostToolUse", arg: "post-tool-use", matcher: "*" },
  { event: "PostToolBatch", arg: "post-tool-batch", recent: true },
];

/** Is a settings file wired with the current PreToolUse matcher? */
export function claudeCodeMatcherCurrent(settings: Record<string, any> | undefined): boolean {
  const groups = settings?.hooks?.PreToolUse;
  if (!Array.isArray(groups)) return false;
  return groups.some((g: HookGroup) => g.matcher === PRE_TOOL_MATCHER && (g.hooks ?? []).some((h) => isSecretgateHook(h.command, "claude-code")));
}

/** Is a settings file wired with the hook that checks failed tool calls? */
export function claudeCodeBatchHookWired(settings: Record<string, any> | undefined): boolean {
  const groups = settings?.hooks?.PostToolBatch;
  return Array.isArray(groups) && groups.some((g: HookGroup) => (g.hooks ?? []).some((h) => isSecretgateHook(h.command, "claude-code")));
}

interface HookGroup {
  matcher?: string;
  hooks: Array<{ type: string; command: string; timeout?: number }>;
}

function withoutOurGroups(groups: HookGroup[] | undefined): HookGroup[] {
  if (!Array.isArray(groups)) return [];
  return groups.map((g) => ({ ...g, hooks: (g.hooks ?? []).filter((h) => !isSecretgateHook(h.command, "claude-code")) })).filter((g) => g.hooks.length > 0);
}

export interface InstallOptions {
  settingsPath: string;
  /** how the agent should invoke the CLI, e.g. `node /home/u/.secretgate/bin/secretgate.mjs` */
  command: string;
  /** The Claude Code that will read the file, as `claude --version` prints
   *  it. PostToolBatch is written only for one that tolerates it. */
  claudeVersion?: string;
  /** The tree the settings belong to: a symlinked settings file is written
   *  through only when it resolves inside it. Default: the directory that
   *  holds `.claude/` — the project for project settings, the home directory
   *  for the global ones. */
  root?: string;
}

// Both files secretgate touches, checked before either is read or written: a
// link that leaves the tree stops the whole operation (see assertWithin).
function settingsTree(settingsPath: string, root: string | undefined): { ownershipPath: string; within: string[] } {
  const ownershipPath = `${settingsPath}.secretgate-ownership.json`;
  const within = [root ?? dirname(dirname(settingsPath))];
  assertWithin(settingsPath, within);
  assertWithin(ownershipPath, within);
  return { ownershipPath, within };
}

export function installClaudeCode({ settingsPath, command, root, claudeVersion }: InstallOptions): EditReport {
  const recentEvents = claudeCodeTakesBatchHook(claudeVersion);
  const { ownershipPath, within } = settingsTree(settingsPath, root);
  const previous = existsSync(ownershipPath) ? JSON.parse(readFileSync(ownershipPath, "utf8")) : {};
  const added: string[] = [];
  const adopted: string[] = [];
  const report = editJsonFile(
    settingsPath,
    (s) => {
      s.hooks ??= {};
      for (const { event, arg, matcher, recent } of EVENTS) {
        const kept = withoutOurGroups(s.hooks[event]);
        if (recent && !recentEvents) {
          // Not for this Claude Code: ours is taken out if an earlier install put it there.
          if (kept.length > 0) s.hooks[event] = kept;
          else delete s.hooks[event];
          continue;
        }
        // 30s cap (seconds): a hung hook must not stall every tool call for the 600s default.
        const group: HookGroup = { hooks: [{ type: "command", command: `${command} hook claude-code ${arg}`, timeout: 30 }] };
        if (matcher) group.matcher = matcher;
        s.hooks[event] = [...kept, group];
      }
      s.permissions ??= {};
      // Rules an older secretgate added and no longer ships (e.g. `**/*.pem`,
      // which blocked test fixtures) are removed — only the ones it owns.
      const current: string[] = Array.isArray(s.permissions.deny) ? s.permissions.deny : [];
      const owned: string[] = previous.deny ?? [];
      const retired = new Set([...owned.filter((r) => !CC_DENY_RULES.includes(r)), ...retiredRulesToRemove(current, owned)]);
      const deny = current.filter((r) => !retired.has(r));
      added.push(...CC_DENY_RULES.filter((r) => !deny.includes(r)));
      // Rules an older secretgate installed are recorded too, or uninstall would
      // leave them behind once a record exists.
      adopted.push(...unrecordedLegacyRules(current, previous.deny));
      s.permissions.deny = [...deny, ...added];
    },
    { within },
  );
  editJsonFile(
    ownershipPath,
    (state) => {
      state.deny = [...new Set([...(previous.deny ?? []), ...added, ...adopted])].filter((r) => CC_DENY_RULES.includes(r));
    },
    { latestBackupOnly: true, within },
  );
  return report;
}

export function uninstallClaudeCode({ settingsPath, root }: { settingsPath: string; root?: string }): EditReport {
  const { ownershipPath, within } = settingsTree(settingsPath, root);
  const recorded: string[] | undefined = existsSync(ownershipPath) ? (JSON.parse(readFileSync(ownershipPath, "utf8")).deny ?? []) : undefined;
  const report = editJsonFile(
    settingsPath,
    (s) => {
      if (s.hooks && typeof s.hooks === "object") {
        for (const { event } of EVENTS) {
          const kept = withoutOurGroups(s.hooks[event]);
          if (kept.length > 0) s.hooks[event] = kept;
          else delete s.hooks[event];
        }
        // An object install created and uninstall emptied is not left behind.
        if (Object.keys(s.hooks).length === 0) delete s.hooks;
      }
      if (Array.isArray(s.permissions?.deny)) {
        // secretgate <= 1.4 kept no ownership record, and the upgrades that
        // started one did not adopt its rules (see unrecordedLegacyRules).
        const deny: unknown[] = s.permissions.deny;
        const owned = [...(recorded ?? []), ...unrecordedLegacyRules(deny, recorded)];
        s.permissions.deny = deny.filter((r) => !(typeof r === "string" && owned.includes(r)));
        if (s.permissions.deny.length === 0) delete s.permissions.deny;
        if (Object.keys(s.permissions).length === 0) delete s.permissions;
      }
    },
    { within },
  );
  if (existsSync(ownershipPath)) rmSync(ownershipPath);
  return report;
}
