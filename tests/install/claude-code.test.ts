import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { CC_DENY_RULES, installClaudeCode, uninstallClaudeCode } from "../../src/install/claude-code.js";
import { SettingsParseError } from "../../src/install/json-merge.js";

let dir: string;
let settingsPath: string;
const command = "node /home/u/.secretgate/bin/secretgate.mjs";

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "secretgate-install-"));
  settingsPath = join(dir, "settings.json");
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

const read = () => JSON.parse(readFileSync(settingsPath, "utf8"));

describe("installClaudeCode", () => {
  it("creates settings.json from scratch with 3 hook events + deny rules", () => {
    const r = installClaudeCode({ settingsPath, command });
    expect(r.changed).toBe(true);
    const s = read();
    expect(s.hooks.UserPromptSubmit[0].hooks[0].command).toBe(`${command} hook claude-code user-prompt-submit`);
    expect(s.hooks.PreToolUse[0].matcher).toBe("Read|Grep|Edit|Write|MultiEdit|NotebookEdit|Bash");
    // PostToolUse redacts EVERY tool's output (incl. MCP/custom), so matcher is "*"
    expect(s.hooks.PostToolUse[0].matcher).toBe("*");
    for (const rule of CC_DENY_RULES) expect(s.permissions.deny).toContain(rule);
  });

  it("preserves existing user hooks and permissions", () => {
    writeFileSync(
      settingsPath,
      JSON.stringify({
        permissions: { deny: ["Read(./private/**)"], defaultMode: "auto" },
        hooks: { Stop: [{ hooks: [{ type: "command", command: "/my/notify.sh" }] }] },
        model: "fable",
      }),
    );
    installClaudeCode({ settingsPath, command });
    const s = read();
    expect(s.model).toBe("fable");
    expect(s.permissions.defaultMode).toBe("auto");
    expect(s.permissions.deny).toContain("Read(./private/**)");
    expect(s.hooks.Stop[0].hooks[0].command).toBe("/my/notify.sh");
    expect(s.hooks.UserPromptSubmit).toHaveLength(1);
  });

  it("is idempotent — re-running replaces our entries, never duplicates", () => {
    installClaudeCode({ settingsPath, command });
    const r2 = installClaudeCode({ settingsPath, command });
    expect(r2.changed).toBe(false);
    const r3 = installClaudeCode({ settingsPath, command: "node /new/path/secretgate.mjs" });
    expect(r3.changed).toBe(true);
    const s = read();
    expect(s.hooks.UserPromptSubmit).toHaveLength(1);
    expect(s.hooks.UserPromptSubmit[0].hooks[0].command).toContain("/new/path/");
    expect(s.permissions.deny.filter((d: string) => d === CC_DENY_RULES[0])).toHaveLength(1);
  });

  it("backs up an existing file before the first change", () => {
    writeFileSync(settingsPath, JSON.stringify({ model: "fable" }));
    installClaudeCode({ settingsPath, command });
    const backups = readdirSync(dir).filter((f) => f.includes("secretgate-backup"));
    expect(backups).toHaveLength(1);
    expect(JSON.parse(readFileSync(join(dir, backups[0]!), "utf8")).model).toBe("fable");
  });

  it("refuses to touch corrupt JSON and reports it", () => {
    writeFileSync(settingsPath, "{ model: broken,, }");
    expect(() => installClaudeCode({ settingsPath, command })).toThrow(SettingsParseError);
    expect(readFileSync(settingsPath, "utf8")).toBe("{ model: broken,, }");
  });
});

describe("uninstallClaudeCode", () => {
  it("removes exactly what install added, leaving user config intact", () => {
    writeFileSync(
      settingsPath,
      JSON.stringify({
        permissions: { deny: ["Read(./private/**)"] },
        hooks: { Stop: [{ hooks: [{ type: "command", command: "/my/notify.sh" }] }] },
      }),
    );
    installClaudeCode({ settingsPath, command });
    const r = uninstallClaudeCode({ settingsPath });
    expect(r.changed).toBe(true);
    const s = read();
    expect(s.hooks.UserPromptSubmit).toBeUndefined();
    expect(s.hooks.PreToolUse).toBeUndefined();
    expect(s.hooks.PostToolUse).toBeUndefined();
    expect(s.hooks.Stop[0].hooks[0].command).toBe("/my/notify.sh");
    expect(s.permissions.deny).toEqual(["Read(./private/**)"]);
  });

  it("is a no-op on a file we never touched", () => {
    writeFileSync(settingsPath, JSON.stringify({ model: "fable" }));
    const r = uninstallClaudeCode({ settingsPath });
    expect(r.changed).toBe(false);
    expect(read().model).toBe("fable");
  });

  it("is a no-op when the file does not exist", () => {
    const r = uninstallClaudeCode({ settingsPath });
    expect(r.changed).toBe(false);
    expect(existsSync(settingsPath)).toBe(false);
  });
});
