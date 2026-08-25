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
    expect(parsed.hooks.PostToolUse[0].matcher).toBe(".*");
    expect(parsed.hooks.PostToolUse[0].hooks[0].command).toBe(`${command} hook codex post-tool-use`);
  });

  it("enables the hooks feature gate in config.toml, preserving user content", () => {
    writeFileSync(join(dir, "config.toml"), 'model = "o4"\n');
    const r = installCodex({ codexDir: dir, command });
    expect(r.configChanged).toBe(true);
    const toml = readFileSync(join(dir, "config.toml"), "utf8");
    expect(toml).toContain('model = "o4"');
    expect(toml).toContain("hooks = true");
  });

  it("trusts the exact installed hooks so Codex does not prompt or skip them", () => {
    writeFileSync(
      join(dir, "hooks.json"),
      JSON.stringify({ hooks: { PostToolUse: [{ matcher: ".*", hooks: [{ type: "command", command: "/foreign.sh" }] }] } }),
    );

    installCodex({ codexDir: dir, command });

    const toml = readFileSync(join(dir, "config.toml"), "utf8");
    expect(toml).toContain(`${join(dir, "hooks.json")}:user_prompt_submit:0:0`);
    expect(toml).toContain(`${join(dir, "hooks.json")}:pre_tool_use:0:0`);
    expect(toml).toContain(`${join(dir, "hooks.json")}:post_tool_use:1:0`);
    expect(toml.match(/trusted_hash = "sha256:[a-f0-9]{64}"/g)).toHaveLength(3);
  });

  it("preserves native MCP hooks that have no command field", () => {
    writeFileSync(
      join(dir, "hooks.json"),
      JSON.stringify({
        hooks: {
          PostToolUse: [{ matcher: ".*", hooks: [{ type: "mcp_tool", server: "audit", tool: "record" }] }],
        },
      }),
    );

    expect(() => installCodex({ codexDir: dir, command })).not.toThrow();
    const parsed = JSON.parse(readFileSync(join(dir, "hooks.json"), "utf8"));
    expect(parsed.hooks.PostToolUse[0].hooks[0]).toEqual({ type: "mcp_tool", server: "audit", tool: "record" });
    expect(parsed.hooks.PostToolUse[1].hooks[0].command).toContain("hook codex post-tool-use");
  });

  it("is idempotent", () => {
    installCodex({ codexDir: dir, command });
    const r2 = installCodex({ codexDir: dir, command });
    expect(r2.hooks.changed).toBe(false);
    expect(r2.configChanged).toBe(false);
  });

  it("explains Codex block-and-replace output protection", () => {
    const r = installCodex({ codexDir: dir, command });
    const guidance = r.guidance.join("\n");
    expect(guidance).not.toMatch(/codex exec/);
    expect(guidance).toMatch(/block-and-replace/i);
    expect(guidance).not.toMatch(/not possible|not covered/i);
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

  it("removes only Secretgate hook trust and preserves a foreign hook state", () => {
    const foreignKey = `${join(dir, "hooks.json")}:post_tool_use:0:0`;
    writeFileSync(
      join(dir, "hooks.json"),
      JSON.stringify({ hooks: { PostToolUse: [{ matcher: ".*", hooks: [{ type: "command", command: "/foreign.sh" }] }] } }),
    );
    writeFileSync(join(dir, "config.toml"), `[hooks.state."${foreignKey}"]\ntrusted_hash = "sha256:foreign"\n`);
    installCodex({ codexDir: dir, command });

    uninstallCodex({ codexDir: dir });

    const toml = readFileSync(join(dir, "config.toml"), "utf8");
    expect(toml).toContain(`[hooks.state."${foreignKey}"]`);
    expect(toml).toContain('trusted_hash = "sha256:foreign"');
    expect(toml).not.toContain(":user_prompt_submit:0:0");
    expect(toml).not.toContain(":pre_tool_use:0:0");
    expect(toml).not.toContain(":post_tool_use:1:0");
  });

  it("preserves Codex settings appended inside a legacy managed block", () => {
    writeFileSync(
      join(dir, "config.toml"),
      `model = "gpt-5.6-sol"
# >>> secretgate managed >>>
notify = ["/usr/local/bin/notify"]

[features]
hooks = true
js_repl = false

[plugins.browser]
enabled = true

[mcp_servers.node_repl]
command = "/usr/local/bin/node_repl"
# <<< secretgate managed <<<`,
    );
    writeFileSync(
      join(dir, "hooks.json"),
      JSON.stringify({
        hooks: {
          UserPromptSubmit: [{ hooks: [{ type: "command", command: `${command} hook codex user-prompt-submit` }] }],
          PreToolUse: [{ matcher: ".*", hooks: [{ type: "command", command: `${command} hook codex pre-tool-use` }] }],
        },
      }),
    );

    uninstallCodex({ codexDir: dir });

    const toml = readFileSync(join(dir, "config.toml"), "utf8");
    expect(toml).toContain('notify = ["/usr/local/bin/notify"]');
    expect(toml).toContain("[features]\njs_repl = false");
    expect(toml).toContain("[plugins.browser]\nenabled = true");
    expect(toml).toContain('[mcp_servers.node_repl]\ncommand = "/usr/local/bin/node_repl"');
    expect(toml).not.toContain("secretgate managed");
    expect(toml).not.toMatch(/^hooks\s*=\s*true$/m);
  });
});
