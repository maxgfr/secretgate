import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readFileSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { writeFileAtomic } from "../fs-atomic.js";
import { isSecretgateHook } from "./hook-marker.js";
import { canonicalize, type EditReport, editJsonFile } from "./json-merge.js";
import {
  disableHooksFeature,
  enableHooksFeature,
  type HookTrustEntry,
  hooksFeatureEnabled,
  removeHookTrust,
  staleHookTrustKeys,
  upsertHookTrust,
} from "./toml-touch.js";

export function codexHome(): string {
  return process.env.CODEX_HOME ?? join(homedir(), ".codex");
}

interface HookGroup {
  matcher?: string;
  hooks: Array<{ type: string; command?: string; timeout?: number; async?: boolean; statusMessage?: string }>;
}

function withoutOurGroups(groups: HookGroup[] | undefined): HookGroup[] {
  if (!Array.isArray(groups)) return [];
  return groups.map((g) => ({ ...g, hooks: (g.hooks ?? []).filter((h) => !isSecretgateHook(h.command, "codex")) })).filter((g) => g.hooks.length > 0);
}

// Codex does not apply PostToolUse output-rewrite fields, but decision:block
// replaces the model-visible result with the hook's safe feedback. Wire all
// three protection surfaces. hooks.json REQUIRES the top-level {"hooks":{}}
// wrapper (a documented footgun).
const EVENTS: Array<{ event: string; arg: string; matcher?: string }> = [
  { event: "UserPromptSubmit", arg: "user-prompt-submit" },
  { event: "PreToolUse", arg: "pre-tool-use", matcher: ".*" },
  { event: "PostToolUse", arg: "post-tool-use", matcher: ".*" },
];

/** How many hooks a complete Codex install wires (and must trust). */
export const CODEX_HOOK_COUNT = EVENTS.length;

const EVENT_KEY: Record<string, string> = {
  UserPromptSubmit: "user_prompt_submit",
  PreToolUse: "pre_tool_use",
  PostToolUse: "post_tool_use",
};

function hookTrustHash(event: string, group: HookGroup, handler: HookGroup["hooks"][number]): string {
  if (typeof handler.command !== "string") throw new Error("cannot trust a command hook without a command");
  const normalizedHandler = {
    type: "command",
    command: handler.command,
    timeout: Math.max(handler.timeout ?? 600, 1),
    async: handler.async ?? false,
    ...(handler.statusMessage === undefined ? {} : { statusMessage: handler.statusMessage }),
  };
  const identity = {
    event_name: EVENT_KEY[event],
    ...(event === "UserPromptSubmit" || group.matcher === undefined ? {} : { matcher: group.matcher }),
    hooks: [normalizedHandler],
  };
  const serialized = JSON.stringify(canonicalize(identity));
  return `sha256:${createHash("sha256").update(serialized).digest("hex")}`;
}

function ourHookTrustEntries(hooksPath: string): HookTrustEntry[] {
  const root = JSON.parse(readFileSync(hooksPath, "utf8")) as { hooks?: Record<string, HookGroup[]> };
  const entries: HookTrustEntry[] = [];
  for (const { event } of EVENTS) {
    for (const [groupIndex, group] of (root.hooks?.[event] ?? []).entries()) {
      for (const [handlerIndex, handler] of (group.hooks ?? []).entries()) {
        if (typeof handler.command !== "string" || !isSecretgateHook(handler.command, "codex")) continue;
        entries.push({
          key: `${hooksPath}:${EVENT_KEY[event]}:${groupIndex}:${handlerIndex}`,
          trustedHash: hookTrustHash(event, group, handler),
        });
      }
    }
  }
  return entries;
}

export function codexWiringStatus(codexDir: string): { trusted: number; expected: number; feature: boolean } {
  try {
    const hooksPath = join(realpathSync(codexDir), "hooks.json");
    const config = readFileSync(join(codexDir, "config.toml"), "utf8");
    const entries = ourHookTrustEntries(hooksPath);
    const tables = config.split(/(?=^\s*\[)/m);
    const trusted = entries.filter((entry) =>
      tables.some((table) => {
        const lines = table.trim().split(/\r?\n/);
        return (
          lines[0]?.trim() === `[hooks.state.${JSON.stringify(entry.key)}]` &&
          lines.some((line) => line.trim() === `trusted_hash = ${JSON.stringify(entry.trustedHash)}`) &&
          !lines.some((line) => /^\s*enabled\s*=\s*false\b/.test(line))
        );
      }),
    ).length;
    return { trusted, expected: entries.length, feature: hooksFeatureEnabled(config) };
  } catch {
    return { trusted: 0, expected: 0, feature: false };
  }
}

function writeTextWithBackup(path: string, content: string): void {
  if (existsSync(path)) {
    const stamp = new Date().toISOString().replaceAll(/[:.]/g, "-");
    copyFileSync(path, `${path}.secretgate-backup-${stamp}`);
  }
  writeFileAtomic(path, content, 0o644);
}

// Our trust entries for hooksPath at keys we no longer occupy (see staleHookTrustKeys).
function withoutStaleTrust(content: string, hooksPath: string, ours: HookTrustEntry[], keep: string[]): ReturnType<typeof removeHookTrust> {
  const stale = staleHookTrustKeys(content, hooksPath, new Set(ours.map((e) => e.trustedHash)), new Set(keep));
  return removeHookTrust(content, stale);
}

export interface CodexInstallReport {
  hooks: EditReport;
  configChanged: boolean;
  guidance: string[];
}

export function installCodex({ codexDir, command }: { codexDir: string; command: string }): CodexInstallReport {
  mkdirSync(codexDir, { recursive: true });
  const hooksPath = join(realpathSync(codexDir), "hooks.json");
  const hooksReport = editJsonFile(hooksPath, (root) => {
    root.hooks ??= {};
    for (const { event, arg, matcher } of EVENTS) {
      const kept = withoutOurGroups(root.hooks[event]);
      const group: HookGroup = {
        hooks: [{ type: "command", command: `${command} hook codex ${arg}`, timeout: 30, statusMessage: "secretgate" }],
      };
      if (matcher) group.matcher = matcher;
      root.hooks[event] = [...kept, group];
    }
  });

  const configPath = join(codexDir, "config.toml");
  const current = existsSync(configPath) ? readFileSync(configPath, "utf8") : "";
  const featureEdit = enableHooksFeature(current);
  const legacyPath = resolve(codexDir, "hooks.json");
  const legacyKeys = legacyPath === hooksPath ? [] : ourHookTrustEntries(hooksPath).map((entry) => entry.key.replace(hooksPath, legacyPath));
  const migrated = removeHookTrust(featureEdit.content, legacyKeys);
  const ours = ourHookTrustEntries(hooksPath);
  const pruned = withoutStaleTrust(
    migrated.content,
    hooksPath,
    ours,
    ours.map((e) => e.key),
  );
  const trustEdit = upsertHookTrust(pruned.content, ours);
  const configChanged = featureEdit.changed || migrated.changed || pruned.changed || trustEdit.changed;
  if (configChanged) writeTextWithBackup(configPath, trustEdit.content);

  return {
    hooks: hooksReport,
    configChanged,
    guidance: [
      "codex: tool outputs are protected with PostToolUse block-and-replace: when a secret is found, Codex rejects the raw result and gives the model only Secretgate's locally redacted replacement.",
      'codex: for OS-enforced file protection, consider a permissions profile in config.toml, e.g.:\n  [permissions.secretgate.filesystem.":workspace_roots"]\n  "**/*.env" = "deny"\n  (not added automatically — it does not compose with legacy sandbox_mode settings).',
    ],
  };
}

export function uninstallCodex({ codexDir }: { codexDir: string }): { hooks: EditReport; configChanged: boolean } {
  const hooksPath = existsSync(codexDir) ? join(realpathSync(codexDir), "hooks.json") : resolve(codexDir, "hooks.json");
  const ours = existsSync(hooksPath) ? ourHookTrustEntries(hooksPath) : [];
  const trustKeys = ours.map((entry) => entry.key);
  let hooksReport: EditReport = { path: hooksPath, changed: false };
  if (existsSync(hooksPath)) {
    hooksReport = editJsonFile(hooksPath, (root) => {
      if (root.hooks && typeof root.hooks === "object") {
        for (const { event } of EVENTS) {
          const kept = withoutOurGroups(root.hooks[event]);
          if (kept.length > 0) root.hooks[event] = kept;
          else delete root.hooks[event];
        }
        if (Object.keys(root.hooks).length === 0) delete root.hooks;
      }
    });
  }
  const configPath = join(codexDir, "config.toml");
  let configChanged = false;
  if (existsSync(configPath)) {
    const current = readFileSync(configPath, "utf8");
    const removed = removeHookTrust(current, trustKeys);
    const stale = withoutStaleTrust(removed.content, hooksPath, ours, []);
    const trustEdit = { content: stale.content, changed: removed.changed || stale.changed };
    const remaining = existsSync(hooksPath) ? JSON.parse(readFileSync(hooksPath, "utf8")).hooks : undefined;
    // The shared feature gate also enables foreign/inline/plugin hooks.
    const foreignHooks = remaining && Object.keys(remaining).length > 0;
    const sharedConfig = /\[hooks\.(?!state\b)|\[plugins\./.test(trustEdit.content);
    const featureEdit = foreignHooks || sharedConfig ? { content: trustEdit.content, changed: false } : disableHooksFeature(trustEdit.content);
    if (trustEdit.changed || featureEdit.changed) {
      writeTextWithBackup(configPath, featureEdit.content);
      configChanged = true;
    }
  }
  return { hooks: hooksReport, configChanged };
}
