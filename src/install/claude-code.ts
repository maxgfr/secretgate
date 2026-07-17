import { type EditReport, editJsonFile } from "./json-merge.js";

// Deny rules complement the hooks: they also apply where tool hooks don't fire
// — notably @file mentions, which inline a file's content WITHOUT firing tool
// hooks. Kept close to parity with paths.ts SENSITIVE_GLOBS so @file can't pull
// in a key the hook layer would have denied. .env.example & co stay readable
// because the hook is the precise, exemption-aware layer (deny globs can't
// express negation, so we avoid the broad `**/.env.*` here).
export const CC_DENY_RULES = [
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

// Identifies OUR hook entries regardless of how the CLI is invoked
// (`secretgate hook claude-code …`, `node …/secretgate.mjs hook claude-code …`).
const MARKER = "hook claude-code";

// PostToolUse redaction is the linchpin control, so it fires on EVERY tool
// (matcher "*") — an allow-list would silently miss MCP tools, custom tools and
// any future tool, letting their output reach the model unredacted. The
// deep-walk handles whatever shape the result has. PreToolUse stays targeted:
// its deny/restore logic only applies to the file/shell tools named here, and
// any secret an MCP read tool pulls in is still redacted by PostToolUse.
const EVENTS: Array<{ event: string; arg: string; matcher?: string }> = [
  { event: "UserPromptSubmit", arg: "user-prompt-submit" },
  { event: "PreToolUse", arg: "pre-tool-use", matcher: "Read|Grep|Edit|Write|MultiEdit|NotebookEdit|Bash" },
  { event: "PostToolUse", arg: "post-tool-use", matcher: "*" },
];

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
  return editJsonFile(settingsPath, (s) => {
    s.hooks ??= {};
    for (const { event, arg, matcher } of EVENTS) {
      const kept = withoutOurGroups(s.hooks[event]);
      // 30s cap (seconds): a hung hook must not stall every tool call for the 600s default.
      const group: HookGroup = { hooks: [{ type: "command", command: `${command} hook claude-code ${arg}`, timeout: 30 }] };
      if (matcher) group.matcher = matcher;
      s.hooks[event] = [...kept, group];
    }
    s.permissions ??= {};
    const deny: string[] = Array.isArray(s.permissions.deny) ? s.permissions.deny : [];
    s.permissions.deny = [...deny, ...CC_DENY_RULES.filter((r) => !deny.includes(r))];
  });
}

export function uninstallClaudeCode({ settingsPath }: { settingsPath: string }): EditReport {
  return editJsonFile(settingsPath, (s) => {
    if (s.hooks && typeof s.hooks === "object") {
      for (const { event } of EVENTS) {
        const kept = withoutOurGroups(s.hooks[event]);
        if (kept.length > 0) s.hooks[event] = kept;
        else delete s.hooks[event];
      }
    }
    if (Array.isArray(s.permissions?.deny)) {
      s.permissions.deny = s.permissions.deny.filter((r: string) => !CC_DENY_RULES.includes(r));
      if (s.permissions.deny.length === 0) delete s.permissions.deny;
      if (Object.keys(s.permissions).length === 0) delete s.permissions;
    }
  });
}
