import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { type EditReport, editJsonFile } from "./json-merge.js";

// OpenCode install = copy the self-contained plugin bundle to
// <config>/plugin/secretgate.js. secretgate is distributed as a skill, not an
// npm package, so there is no npm-pin mode — the file copy works fully offline.
const OWNERSHIP_MARKER = "SecretgatePlugin";

export function opencodeConfigDir(): string {
  const xdg = process.env.XDG_CONFIG_HOME;
  return join(xdg && xdg !== "" ? xdg : join(homedir(), ".config"), "opencode");
}

export interface OpencodeInstallOptions {
  configDir: string;
  /** path to the built scripts/secretgate-opencode.mjs to copy */
  pluginSource: string;
}

export function installOpencode({ configDir, pluginSource }: OpencodeInstallOptions): EditReport {
  const target = join(configDir, "plugin", "secretgate.js");
  const content = readFileSync(pluginSource, "utf8");
  if (existsSync(target)) {
    const existing = readFileSync(target, "utf8");
    if (!existing.includes(OWNERSHIP_MARKER)) {
      throw new Error(`refusing to overwrite ${target}: the existing file is not ours (foreign plugin?). Remove it manually first.`);
    }
    if (existing === content) return { path: target, changed: false };
  }
  mkdirSync(join(configDir, "plugin"), { recursive: true });
  writeFileSync(target, content);
  return { path: target, changed: true };
}

export function uninstallOpencode({ configDir }: { configDir: string }): EditReport {
  let changed = false;
  const target = join(configDir, "plugin", "secretgate.js");
  if (existsSync(target) && readFileSync(target, "utf8").includes(OWNERSHIP_MARKER)) {
    rmSync(target);
    changed = true;
  }
  const configPath = join(configDir, "opencode.json");
  if (existsSync(configPath)) {
    const r = editJsonFile(configPath, (cfg) => {
      if (Array.isArray(cfg.plugin)) {
        cfg.plugin = cfg.plugin.filter((p: string) => !/^secretgate@/.test(p));
        if (cfg.plugin.length === 0) delete cfg.plugin;
      }
    });
    changed = changed || r.changed;
  }
  return { path: target, changed };
}
