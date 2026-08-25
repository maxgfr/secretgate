import { describe, expect, it } from "vitest";
import { disableHooksFeature, enableHooksFeature, removeHookTrust, upsertHookTrust } from "../../src/install/toml-touch.js";

describe("enableHooksFeature — targeted config.toml editing without a TOML parser", () => {
  it("creates a managed block when the file is empty/missing", () => {
    const r = enableHooksFeature("");
    expect(r.changed).toBe(true);
    expect(r.content).toContain(">>> secretgate managed >>>");
    expect(r.content).toContain("[features]");
    expect(r.content).toContain("hooks = true");
    expect(r.content).toContain("<<< secretgate managed <<<");
  });

  it("appends the managed block after existing content", () => {
    const r = enableHooksFeature('model = "o4"\napproval_policy = "on-request"\n');
    expect(r.changed).toBe(true);
    expect(r.content).toContain('model = "o4"');
    expect(r.content.indexOf("[features]")).toBeGreaterThan(r.content.indexOf('model = "o4"'));
  });

  it("patches INSIDE an existing [features] table instead of duplicating it", () => {
    const r = enableHooksFeature('model = "o4"\n\n[features]\nweb_search = true\n\n[tui]\ntheme = "dark"\n');
    expect(r.changed).toBe(true);
    expect(r.content.match(/\[features\]/g)).toHaveLength(1);
    const featuresBlock = r.content.slice(r.content.indexOf("[features]"), r.content.indexOf("[tui]"));
    expect(featuresBlock).toContain("hooks = true # secretgate");
    expect(featuresBlock).toContain("web_search = true");
  });

  it("is a no-op when hooks = true is already set", () => {
    const r = enableHooksFeature("[features]\nhooks = true\n");
    expect(r.changed).toBe(false);
  });

  it("refuses when hooks = false is explicitly set (prints manual guidance)", () => {
    expect(() => enableHooksFeature("[features]\nhooks = false\n")).toThrow(/hooks = false|manually/);
  });

  it("is idempotent — running twice changes nothing the second time", () => {
    const once = enableHooksFeature('model = "o4"\n');
    const twice = enableHooksFeature(once.content);
    expect(twice.changed).toBe(false);
  });
});

describe("disableHooksFeature — uninstall mirror", () => {
  it("removes the managed block", () => {
    const installed = enableHooksFeature('model = "o4"\n').content;
    const r = disableHooksFeature(installed);
    expect(r.changed).toBe(true);
    expect(r.content).not.toContain("secretgate managed");
    expect(r.content).not.toContain("[features]");
    expect(r.content).toContain('model = "o4"');
  });

  it("preserves settings that Codex later wrote inside a legacy managed block", () => {
    const legacyConfig = `model = "gpt-5.6-sol"
# >>> secretgate managed >>>
notify = ["/usr/local/bin/notify"]

[features]
hooks = true
js_repl = false

[plugins.browser]
enabled = true

[mcp_servers.node_repl]
command = "/usr/local/bin/node_repl"
# <<< secretgate managed <<<`;

    const r = disableHooksFeature(legacyConfig);

    expect(r.changed).toBe(true);
    expect(r.content).not.toContain("secretgate managed");
    expect(r.content).not.toMatch(/^hooks\s*=\s*true$/m);
    expect(r.content).toContain('notify = ["/usr/local/bin/notify"]');
    expect(r.content).toContain("[features]\njs_repl = false");
    expect(r.content).toContain("[plugins.browser]\nenabled = true");
    expect(r.content).toContain('[mcp_servers.node_repl]\ncommand = "/usr/local/bin/node_repl"');
  });

  it("removes only OUR line from a shared [features] table", () => {
    const installed = enableHooksFeature("[features]\nweb_search = true\n").content;
    const r = disableHooksFeature(installed);
    expect(r.content).toContain("web_search = true");
    expect(r.content).not.toContain("hooks = true # secretgate");
    expect(r.content).toContain("[features]");
  });

  it("leaves a user's own hooks = true alone", () => {
    const r = disableHooksFeature("[features]\nhooks = true\n");
    expect(r.changed).toBe(false);
    expect(r.content).toContain("hooks = true");
  });
});

describe("Codex hook trust state — targeted config.toml editing", () => {
  const first = {
    key: "/home/u/.codex/hooks.json:user_prompt_submit:0:0",
    trustedHash: `sha256:${"a".repeat(64)}`,
  };
  const second = {
    key: "/home/u/.codex/hooks.json:post_tool_use:1:0",
    trustedHash: `sha256:${"b".repeat(64)}`,
  };

  it("appends trusted hashes without changing unrelated config", () => {
    const r = upsertHookTrust('model = "gpt-5.6-sol"\n', [first, second]);

    expect(r.changed).toBe(true);
    expect(r.content).toContain('model = "gpt-5.6-sol"');
    expect(r.content).toContain(`[hooks.state."${first.key}"]`);
    expect(r.content).toContain(`trusted_hash = "${first.trustedHash}"`);
    expect(r.content).toContain(`[hooks.state."${second.key}"]`);
    expect(r.content).toContain(`trusted_hash = "${second.trustedHash}"`);
  });

  it("is idempotent and updates only a stale hash", () => {
    const once = upsertHookTrust("", [first]).content;
    expect(upsertHookTrust(once, [first]).changed).toBe(false);

    const updated = upsertHookTrust(once, [{ ...first, trustedHash: second.trustedHash }]);
    expect(updated.changed).toBe(true);
    expect(updated.content).not.toContain(first.trustedHash);
    expect(updated.content).toContain(second.trustedHash);
  });

  it("preserves other fields in an existing hook-state table", () => {
    const original = `[hooks.state."${first.key}"]\nenabled = false\n`;
    const r = upsertHookTrust(original, [first]);

    expect(r.content).toContain("enabled = false");
    expect(r.content).toContain(`trusted_hash = "${first.trustedHash}"`);
  });

  it("removes only the selected trust hashes and preserves foreign state", () => {
    const foreignKey = "/home/u/.codex/hooks.json:post_tool_use:0:0";
    const installed = upsertHookTrust(`[hooks.state."${foreignKey}"]\ntrusted_hash = "sha256:foreign"\n`, [first, second]).content;
    const withSetting = installed.replace(`[hooks.state."${first.key}"]`, `[hooks.state."${first.key}"]\nenabled = false`);
    const r = removeHookTrust(withSetting, [first.key, second.key]);

    expect(r.changed).toBe(true);
    expect(r.content).toContain(`[hooks.state."${foreignKey}"]`);
    expect(r.content).toContain('trusted_hash = "sha256:foreign"');
    expect(r.content).toContain(`[hooks.state."${first.key}"]\nenabled = false`);
    expect(r.content).not.toContain(first.trustedHash);
    expect(r.content).not.toContain(second.key);
  });
});
