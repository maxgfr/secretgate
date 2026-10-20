import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { applyEdits, modify, type ParseError, parse as parseJsonc, printParseErrorCode } from "jsonc-parser";
import { writeFileAtomic } from "../fs-atomic.js";
import { type EditReport, SettingsParseError } from "./json-merge.js";

// OpenCode install = copy the self-contained plugin bundle to
// <config>/plugins/secretgate.js. secretgate is distributed as a skill, not an
// npm package, so there is no npm-pin mode — the file copy works fully offline.
const OWNERSHIP_MARKER = "SecretgatePlugin";

// The directory OpenCode loads `plugins/*.js` from: OPENCODE_CONFIG_DIR when
// set (OpenCode honours it first), else the XDG config home.
export function opencodeConfigDir(): string {
  const custom = process.env.OPENCODE_CONFIG_DIR;
  if (custom && custom !== "") return custom;
  const xdg = process.env.XDG_CONFIG_HOME;
  return join(xdg && xdg !== "" ? xdg : join(homedir(), ".config"), "opencode");
}

/** Where the plugin file lives. */
export function opencodePluginFile(configDir: string): string {
  return join(configDir, "plugins", "secretgate.js");
}

// Earlier releases wrote `plugin/secretgate.js` (singular): OpenCode 2 still
// loads that directory, so a stale copy there would run beside the new one.
function removeStalePlugin(configDir: string): boolean {
  const stale = join(configDir, "plugin", "secretgate.js");
  if (!existsSync(stale) || !readFileSync(stale, "utf8").includes(OWNERSHIP_MARKER)) return false;
  rmSync(stale);
  return true;
}

export type OpencodeInstallOptions = { configDir: string } & (
  | /** path to the built scripts/secretgate-opencode.mjs to copy */
  { pluginSource: string }
  /** the plugin text itself (the standalone binary embeds it) */
  | { pluginContent: string }
);

export function installOpencode(options: OpencodeInstallOptions): EditReport {
  const { configDir } = options;
  const target = opencodePluginFile(configDir);
  const content = "pluginContent" in options ? options.pluginContent : readFileSync(options.pluginSource, "utf8");
  if (existsSync(target)) {
    const existing = readFileSync(target, "utf8");
    if (!existing.includes(OWNERSHIP_MARKER)) {
      throw new Error(`refusing to overwrite ${target}: the existing file is not ours (foreign plugin?). Remove it manually first.`);
    }
    if (existing === content) return { path: target, changed: removeStalePlugin(configDir) };
  }
  mkdirSync(dirname(target), { recursive: true });
  // A running OpenCode may load the plugin while it is being written.
  writeFileAtomic(target, content, 0o644);
  removeStalePlugin(configDir);
  return { path: target, changed: true };
}

// The legacy npm pin (`"plugin": ["secretgate@x"]`) removed from an
// opencode.json / opencode.jsonc, edited in place so comments survive.
// Returns the new text, or undefined when there is nothing to change.
function withoutNpmPin(path: string): string | undefined {
  const text = readFileSync(path, "utf8");
  if (text.trim() === "") return undefined;
  const errors: ParseError[] = [];
  const cfg = parseJsonc(text, errors, { allowTrailingComma: true, disallowComments: false }) as unknown;
  if (errors.length > 0) throw new SettingsParseError(path, printParseErrorCode(errors[0]!.error));
  if (cfg === null || typeof cfg !== "object" || Array.isArray(cfg)) throw new SettingsParseError(path, "top level is not an object");
  const plugin = (cfg as { plugin?: unknown }).plugin;
  if (!Array.isArray(plugin)) return undefined;
  const kept = plugin.filter((p) => !(typeof p === "string" && /^secretgate@/.test(p)));
  if (kept.length === plugin.length) return undefined;
  const fmt = { formattingOptions: { insertSpaces: true, tabSize: 2, eol: text.includes("\r\n") ? "\r\n" : "\n" } };
  return applyEdits(text, modify(text, ["plugin"], kept.length > 0 ? kept : undefined, fmt));
}

export function uninstallOpencode({ configDir }: { configDir: string }): EditReport {
  const target = opencodePluginFile(configDir);
  // Every config is read and checked before anything is removed: a file that
  // cannot be parsed stops the uninstall whole, never half-way.
  const edits: Array<{ path: string; text: string }> = [];
  for (const name of ["opencode.json", "opencode.jsonc"]) {
    const path = join(configDir, name);
    if (!existsSync(path)) continue;
    const text = withoutNpmPin(path);
    if (text !== undefined) edits.push({ path, text });
  }
  let changed = false;
  if (existsSync(target) && readFileSync(target, "utf8").includes(OWNERSHIP_MARKER)) {
    rmSync(target);
    changed = true;
  }
  if (removeStalePlugin(configDir)) changed = true;
  for (const { path, text } of edits) {
    copyFileSync(path, `${path}.secretgate-backup-${new Date().toISOString().replaceAll(/[:.]/g, "-")}`);
    writeFileAtomic(path, text, 0o644);
    changed = true;
  }
  return { path: target, changed };
}
