import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { loadConfig, projectConfigFiles, setTrust } from "../src/config.js";

let root: string;
let home: string;

beforeEach(() => {
  root = realpathSync(mkdtempSync(join(tmpdir(), "secretgate-config-")));
  home = mkdtempSync(join(tmpdir(), "secretgate-config-home-"));
  process.env.SECRETGATE_HOME = home;
  mkdirSync(join(root, ".git"));
  mkdirSync(join(root, "src"));
});

afterEach(() => {
  vi.restoreAllMocks();
  delete process.env.SECRETGATE_HOME;
  rmSync(root, { recursive: true, force: true });
  rmSync(home, { recursive: true, force: true });
});

describe("project config ownership", () => {
  it.skipIf(process.platform === "win32")("ignores a .secretgate.json owned by another account", () => {
    writeFileSync(join(root, ".secretgate.json"), JSON.stringify({ scope: { deny: ["**"] } }));
    expect(projectConfigFiles(join(root, "src"))).toHaveLength(1);
    // Simulate another owner: the file's uid no longer matches the process.
    const uid = statSync(join(root, ".secretgate.json")).uid;
    vi.spyOn(process, "getuid").mockReturnValue(uid + 1);
    expect(projectConfigFiles(join(root, "src"))).toEqual([]);
    const cfg = loadConfig(join(root, "src"));
    expect(cfg.scopes).toEqual([]);
    expect(cfg.error).toBeUndefined();
  });

  it.skipIf(process.platform === "win32")("an invalid file owned by another account cannot block every tool call", () => {
    writeFileSync(join(root, ".secretgate.json"), "{ broken");
    expect(loadConfig(join(root, "src")).error).toBeDefined();
    vi.spyOn(process, "getuid").mockReturnValue(statSync(join(root, ".secretgate.json")).uid + 1);
    expect(loadConfig(join(root, "src")).error).toBeUndefined();
  });
});

describe("trust is judged on the bytes that were parsed", () => {
  it("trusts exactly the current content, and an edit revokes it", () => {
    const file = join(root, ".secretgate.json");
    writeFileSync(file, '{ "allowlist": { "rules": ["x"] } }');
    expect(loadConfig(root).untrusted).toEqual([file]);
    setTrust([file]);
    expect(loadConfig(root).allowlist.rules).toContain("x");
    expect(statSync(join(home, "trusted.json")).mode & 0o777).toBe(0o600);
    writeFileSync(file, '{ "allowlist": { "rules": ["x", "y"] } }');
    const cfg = loadConfig(root);
    expect(cfg.allowlist.rules).not.toContain("y");
    expect(cfg.untrusted).toEqual([file]);
  });

  it("hashes raw bytes, so a file that is not valid UTF-8 never matches a trusted hash by accident", () => {
    const file = join(root, ".secretgate.json");
    writeFileSync(file, Buffer.concat([Buffer.from('{ "allowlist": { "rules": ["x"] } } //'), Buffer.from([0xff, 0xfe])]));
    setTrust([file]);
    expect(loadConfig(root).allowlist.rules).toContain("x");
    expect(JSON.parse(readFileSync(join(home, "trusted.json"), "utf8")).files[file]).toMatch(/^[0-9a-f]{64}$/);
  });
});
