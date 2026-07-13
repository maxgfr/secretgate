import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { UserAllowlist } from "./engine/allowlist.js";
import { defaultVaultHome } from "./vault/vault.js";

// Global config lives next to the vault (~/.secretgate/, overridable via
// SECRETGATE_HOME): config.json for behavior toggles, allowlist.json for the
// user allowlist. A project-level .secretgate.json (in cwd) can add allowlist
// entries — merged additively, it can only ever suppress MORE, never less.

export interface SecretgateConfig {
  /** restore placeholders inside Bash commands (exfiltration risk) — default false */
  restoreBash: boolean;
  /** run the gitleaks binary as a second engine in `scan` when installed */
  hybrid: "auto" | "off";
  allowlist: UserAllowlist;
}

function readJson<T>(path: string): T | undefined {
  try {
    return JSON.parse(readFileSync(path, "utf8")) as T;
  } catch {
    return undefined;
  }
}

export function loadConfig(cwd?: string): SecretgateConfig {
  const home = defaultVaultHome();
  const base = readJson<Partial<SecretgateConfig>>(join(home, "config.json")) ?? {};
  const allow = readJson<UserAllowlist>(join(home, "allowlist.json")) ?? {};
  const project = cwd ? (readJson<{ allowlist?: UserAllowlist }>(join(cwd, ".secretgate.json")) ?? {}) : {};
  const merged: UserAllowlist = {
    sha256: [...(allow.sha256 ?? []), ...(project.allowlist?.sha256 ?? [])],
    rules: [...(allow.rules ?? []), ...(project.allowlist?.rules ?? [])],
    paths: [...(allow.paths ?? []), ...(project.allowlist?.paths ?? [])],
  };
  return {
    restoreBash: base.restoreBash === true,
    hybrid: base.hybrid === "off" ? "off" : "auto",
    allowlist: merged,
  };
}

export function allowlistPath(): string {
  return join(defaultVaultHome(), "allowlist.json");
}
