import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { installOpencode, uninstallOpencode } from "../../src/install/opencode.js";

let dir: string;
let bundle: string;
const bundleContent = `#!/usr/bin/env node\n// fake bundle\nexport const SecretgatePlugin = async () => ({});\n`;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "secretgate-oc-install-"));
  bundle = join(dir, "secretgate-opencode.mjs");
  writeFileSync(bundle, bundleContent);
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

const configDir = () => join(dir, "opencode");

describe("installOpencode (self-contained plugin file)", () => {
  it("copies the plugin bundle into plugin/secretgate.js", () => {
    const r = installOpencode({ configDir: configDir(), pluginSource: bundle });
    expect(r.changed).toBe(true);
    expect(readFileSync(join(configDir(), "plugin", "secretgate.js"), "utf8")).toBe(bundleContent);
  });

  it("is idempotent and overwrites only our own file", () => {
    installOpencode({ configDir: configDir(), pluginSource: bundle });
    const r2 = installOpencode({ configDir: configDir(), pluginSource: bundle });
    expect(r2.changed).toBe(false);
  });

  it("refuses to overwrite a foreign file at the target path", () => {
    mkdirSync(join(configDir(), "plugin"), { recursive: true });
    writeFileSync(join(configDir(), "plugin", "secretgate.js"), "// someone else's plugin\n");
    expect(() => installOpencode({ configDir: configDir(), pluginSource: bundle })).toThrow(/foreign|not ours/i);
  });
});

describe("uninstallOpencode", () => {
  it("removes our plugin file, leaves foreign things alone", () => {
    installOpencode({ configDir: configDir(), pluginSource: bundle });
    const r = uninstallOpencode({ configDir: configDir() });
    expect(r.changed).toBe(true);
    expect(existsSync(join(configDir(), "plugin", "secretgate.js"))).toBe(false);
  });

  it("still cleans up a legacy opencode.json npm pin if present", () => {
    installOpencode({ configDir: configDir(), pluginSource: bundle });
    mkdirSync(configDir(), { recursive: true });
    writeFileSync(join(configDir(), "opencode.json"), JSON.stringify({ plugin: ["other", "secretgate@0.0.1"] }));
    uninstallOpencode({ configDir: configDir() });
    const cfg = JSON.parse(readFileSync(join(configDir(), "opencode.json"), "utf8"));
    expect(cfg.plugin ?? []).not.toContain("secretgate@0.0.1");
  });

  it("does not delete a foreign secretgate.js", () => {
    mkdirSync(join(configDir(), "plugin"), { recursive: true });
    writeFileSync(join(configDir(), "plugin", "secretgate.js"), "// someone else's plugin\n");
    uninstallOpencode({ configDir: configDir() });
    expect(existsSync(join(configDir(), "plugin", "secretgate.js"))).toBe(true);
  });
});
