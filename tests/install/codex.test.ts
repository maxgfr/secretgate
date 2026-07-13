import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { installCodex, uninstallCodex } from "../../src/install/codex.js";

let dir: string;
const command = "node /home/u/.secretgate/bin/secretgate.mjs";

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "secretgate-codex-"));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("installCodex", () => {
  it("writes hooks.json WITH the required top-level hooks wrapper", () => {
    const r = installCodex({ codexDir: dir, command });
    expect(r.hooks.changed).toBe(true);
    const parsed = JSON.parse(readFileSync(join(dir, "hooks.json"), "utf8"));
    expect(Object.keys(parsed)).toEqual(["hooks"]); // the wrapper, nothing else at top level
    expect(parsed.hooks.UserPromptSubmit[0].hooks[0].command).toBe(`${command} hook codex user-prompt-submit`);
    expect(parsed.hooks.PreToolUse[0].matcher).toBe(".*");
    expect(parsed.hooks.PostToolUse).toBeUndefined(); // no working output rewrite in Codex
  });

  it("enables the hooks feature gate in config.toml, preserving user content", () => {
    writeFileSync(join(dir, "config.toml"), 'model = "o4"\n');
    const r = installCodex({ codexDir: dir, command });
    expect(r.configChanged).toBe(true);
    const toml = readFileSync(join(dir, "config.toml"), "utf8");
    expect(toml).toContain('model = "o4"');
    expect(toml).toContain("hooks = true");
  });

  it("is idempotent", () => {
    installCodex({ codexDir: dir, command });
    const r2 = installCodex({ codexDir: dir, command });
    expect(r2.hooks.changed).toBe(false);
    expect(r2.configChanged).toBe(false);
  });

  it("surfaces the codex exec + output-redaction limitations as guidance", () => {
    const r = installCodex({ codexDir: dir, command });
    expect(r.guidance.join("\n")).toMatch(/codex exec/);
    expect(r.guidance.join("\n")).toMatch(/redaction/i);
  });
});

describe("uninstallCodex", () => {
  it("removes our hooks and the feature gate, preserving user config", () => {
    writeFileSync(join(dir, "config.toml"), 'model = "o4"\n');
    installCodex({ codexDir: dir, command });
    const r = uninstallCodex({ codexDir: dir });
    expect(r.hooks.changed).toBe(true);
    expect(r.configChanged).toBe(true);
    const parsed = JSON.parse(readFileSync(join(dir, "hooks.json"), "utf8"));
    expect(parsed.hooks).toBeUndefined();
    const toml = readFileSync(join(dir, "config.toml"), "utf8");
    expect(toml).toContain('model = "o4"');
    expect(toml).not.toContain("secretgate");
  });

  it("keeps foreign hooks intact", () => {
    writeFileSync(join(dir, "hooks.json"), JSON.stringify({ hooks: { UserPromptSubmit: [{ hooks: [{ type: "command", command: "/my/own.sh" }] }] } }));
    installCodex({ codexDir: dir, command });
    uninstallCodex({ codexDir: dir });
    const parsed = JSON.parse(readFileSync(join(dir, "hooks.json"), "utf8"));
    expect(parsed.hooks.UserPromptSubmit[0].hooks[0].command).toBe("/my/own.sh");
  });
});
