import { describe, expect, it } from "vitest";
import { disableHooksFeature, enableHooksFeature } from "../../src/install/toml-touch.js";

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
