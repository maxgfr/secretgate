import { createHash, randomBytes } from "node:crypto";
import { closeSync, copyFileSync, existsSync, mkdirSync, openSync, readFileSync, realpathSync, renameSync, writeSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { type EditReport, editJsonFile } from "./json-merge.js";
import { disableHooksFeature, enableHooksFeature, removeHookTrust, upsertHookTrust, type HookTrustEntry } from "./toml-touch.js";

const MARKER = "hook codex";

export function codexHome(): string {
  return process.env.CODEX_HOME ?? join(homedir(), ".codex");
}

interface HookGroup {
  matcher?: string;
  hooks: Array<{ type: string; command?: string; timeout?: number; async?: boolean; statusMessage?: string }>;
}

function withoutOurGroups(groups: HookGroup[] | undefined): HookGroup[] {
  if (!Array.isArray(groups)) return [];
  return groups.map((g) => ({ ...g, hooks: (g.hooks ?? []).filter((h) => !String(h.command ?? "").includes(MARKER)) })).filter((g) => g.hooks.length > 0);
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

const EVENT_KEY: Record<string, string> = {
  UserPromptSubmit: "user_prompt_submit",
  PreToolUse: "pre_tool_use",
  PostToolUse: "post_tool_use",
};

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
        .map(([key, child]) => [key, canonicalize(child)]),
    );
  }
  return value;
}

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
        if (typeof handler.command !== "string" || !handler.command.includes(MARKER)) continue;
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
        const lines = table.trim().split("\n");
        return (
          lines[0]?.trim() === `[hooks.state.${JSON.stringify(entry.key)}]` &&
          lines.some((line) => line.trim() === `trusted_hash = ${JSON.stringify(entry.trustedHash)}`) &&
          !lines.some((line) => /^\s*enabled\s*=\s*false\b/.test(line))
        );
      }),
    ).length;
    const feature = tables.some((table) => /^\s*\[features\]\s*(?:#.*)?\n/.test(table) && /^\s*hooks\s*=\s*true\b/m.test(table));
    return { trusted, expected: entries.length, feature };
  } catch {
    return { trusted: 0, expected: 0, feature: false };
  }
}

function writeTextWithBackup(path: string, content: string): void {
  if (existsSync(path)) {
    const stamp = new Date().toISOString().replaceAll(/[:.]/g, "-");
    copyFileSync(path, `${path}.secretgate-backup-${stamp}`);
  }
  const tmp = `${path}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
  const fd = openSync(tmp, "w", 0o644);
  try {
    writeSync(fd, content);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, path);
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
  const trustEdit = upsertHookTrust(migrated.content, ourHookTrustEntries(hooksPath));
  if (featureEdit.changed || trustEdit.changed) writeTextWithBackup(configPath, trustEdit.content);

  return {
    hooks: hooksReport,
    configChanged: featureEdit.changed || trustEdit.changed,
    guidance: [
      "codex: tool outputs are protected with PostToolUse block-and-replace: when a secret is found, Codex rejects the raw result and gives the model only Secretgate's locally redacted replacement.",
      'codex: for OS-enforced file protection, consider a permissions profile in config.toml, e.g.:\n  [permissions.secretgate.filesystem.":workspace_roots"]\n  "**/*.env" = "deny"\n  (not added automatically — it does not compose with legacy sandbox_mode settings).',
    ],
  };
}

export function uninstallCodex({ codexDir }: { codexDir: string }): { hooks: EditReport; configChanged: boolean } {
  const hooksPath = existsSync(codexDir) ? join(realpathSync(codexDir), "hooks.json") : resolve(codexDir, "hooks.json");
  const trustKeys = existsSync(hooksPath) ? ourHookTrustEntries(hooksPath).map((entry) => entry.key) : [];
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
    const trustEdit = removeHookTrust(readFileSync(configPath, "utf8"), trustKeys);
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
