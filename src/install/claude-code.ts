import { type EditReport, editJsonFile } from "./json-merge.js";

// Deny rules complement the hooks: they also apply where tool hooks don't fire
// (e.g. cat/head/tail inside Bash, and — partially — @file mentions). Kept
// narrower than the hook layer so .env.example & co stay readable: the hook is
// the precise, exemption-aware layer.
export const CC_DENY_RULES = [
  "Read(**/.env)",
  "Read(**/.env.local)",
  "Read(**/.env.*.local)",
  "Read(**/*.pem)",
  "Read(**/id_rsa*)",
  "Read(**/id_ed25519*)",
  "Read(~/.aws/**)",
  "Read(~/.ssh/**)",
  "Read(~/.kube/config)",
  "Read(**/.netrc)",
  "Read(**/.npmrc)",
];

// Identifies OUR hook entries regardless of how the CLI is invoked
// (`secretgate hook claude-code …`, `node …/secretgate.mjs hook claude-code …`).
const MARKER = "hook claude-code";

const EVENTS: Array<{ event: string; arg: string; matcher?: string }> = [
  { event: "UserPromptSubmit", arg: "user-prompt-submit" },
  { event: "PreToolUse", arg: "pre-tool-use", matcher: "Read|Grep|Edit|Write|MultiEdit|NotebookEdit|Bash" },
  { event: "PostToolUse", arg: "post-tool-use", matcher: "Read|Bash|Grep|Glob|WebFetch" },
];

interface HookGroup {
  matcher?: string;
  hooks: Array<{ type: string; command: string }>;
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
      const group: HookGroup = { hooks: [{ type: "command", command: `${command} hook claude-code ${arg}` }] };
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
