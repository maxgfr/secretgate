import { randomBytes } from "node:crypto";
import { closeSync, copyFileSync, existsSync, openSync, readFileSync, renameSync, writeSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { type EditReport, editJsonFile } from "./json-merge.js";
import { disableHooksFeature, enableHooksFeature } from "./toml-touch.js";

const MARKER = "hook codex";

export function codexHome(): string {
  return process.env.CODEX_HOME ?? join(homedir(), ".codex");
}

interface HookGroup {
  matcher?: string;
  hooks: Array<{ type: string; command: string; timeout?: number; statusMessage?: string }>;
}

function withoutOurGroups(groups: HookGroup[] | undefined): HookGroup[] {
  if (!Array.isArray(groups)) return [];
  return groups.map((g) => ({ ...g, hooks: (g.hooks ?? []).filter((h) => !String(h.command ?? "").includes(MARKER)) })).filter((g) => g.hooks.length > 0);
}

// Codex has no working PostToolUse output rewrite, so only the two events that
// actually protect are wired. hooks.json REQUIRES the top-level {"hooks":{}}
// wrapper (a documented footgun).
const EVENTS: Array<{ event: string; arg: string; matcher?: string }> = [
  { event: "UserPromptSubmit", arg: "user-prompt-submit" },
  { event: "PreToolUse", arg: "pre-tool-use", matcher: ".*" },
];

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
  const hooksReport = editJsonFile(join(codexDir, "hooks.json"), (root) => {
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
  const edit = enableHooksFeature(current);
  if (edit.changed) writeTextWithBackup(configPath, edit.content);

  return {
    hooks: hooksReport,
    configChanged: edit.changed,
    guidance: [
      "codex: hooks protect INTERACTIVE sessions only — a known Codex bug keeps them from firing under `codex exec` (observed on 0.137–0.138).",
      "codex: tool OUTPUT redaction is not possible yet (Codex parses but ignores output rewrites); prompts and tool inputs are covered.",
      'codex: for OS-enforced file protection, consider a permissions profile in config.toml, e.g.:\n  [permissions.secretgate.filesystem.":workspace_roots"]\n  "**/*.env" = "deny"\n  (not added automatically — it does not compose with legacy sandbox_mode settings).',
    ],
  };
}

export function uninstallCodex({ codexDir }: { codexDir: string }): { hooks: EditReport; configChanged: boolean } {
  const hooksPath = join(codexDir, "hooks.json");
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
    const edit = disableHooksFeature(readFileSync(configPath, "utf8"));
    if (edit.changed) {
      writeTextWithBackup(configPath, edit.content);
      configChanged = true;
    }
  }
  return { hooks: hooksReport, configChanged };
}
