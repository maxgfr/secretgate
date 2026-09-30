import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { handleClaudeCode } from "../../src/hooks/claude-code.js";
import { CC_DENY_RULES, installClaudeCode } from "../../src/install/claude-code.js";
import { installCodex } from "../../src/install/codex.js";
import { isSecretgateHook } from "../../src/install/hook-marker.js";
import { FAKE } from "../fixtures/fake-tokens.js";

// Fixing security bugs means reading the fake keys and .env files that test
// suites ship. secretgate must let that work happen — and still keep real
// secrets out of the model.

let home: string;
let base: string;
let proj: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "sg-sw-home-"));
  process.env.SECRETGATE_HOME = home;
  // The project sits under a directory literally named `tests`: that must not
  // exempt the project's own root files.
  base = realpathSync(mkdtempSync(join(tmpdir(), "sg-sw-")));
  proj = join(base, "tests", "proj");
  for (const d of ["tests/fixtures", "testdata", "src", "__mocks__"]) mkdirSync(join(proj, d), { recursive: true });
  writeFileSync(join(proj, "tests", "fixtures", "server.key"), "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n");
  writeFileSync(join(proj, "testdata", ".env"), `GITHUB_TOKEN=${FAKE.githubPat}\n`);
  writeFileSync(join(proj, "src", "server.key"), "real\n");
  writeFileSync(join(proj, ".env"), "REAL=1\n");
});

afterEach(() => {
  delete process.env.SECRETGATE_HOME;
  rmSync(home, { recursive: true, force: true });
  rmSync(base, { recursive: true, force: true });
});

const decide = async (tool_name: string, tool_input: unknown) => {
  const out = (await handleClaudeCode("pre-tool-use", JSON.stringify({ session_id: "w", cwd: proj, tool_name, tool_input }))).stdout;
  return out.trim() ? JSON.parse(out).hookSpecificOutput?.permissionDecision : undefined;
};

describe("test fixtures are readable, real secret locations are not", () => {
  it.each([
    ["Read", { file_path: "tests/fixtures/server.key" }],
    ["Read", { file_path: "testdata/.env" }],
    ["Bash", { command: "cat testdata/.env tests/fixtures/server.key" }],
    ["Grep", { pattern: "TOKEN", path: "testdata", glob: ".env*", output_mode: "content" }],
  ])("%s %j is allowed", async (tool, input) => {
    expect(await decide(tool, input)).toBeUndefined();
  });

  it.each([
    ["Read", { file_path: "src/server.key" }],
    ["Read", { file_path: ".env" }],
    ["Bash", { command: "cat .env" }],
  ])("%s %j is still denied (a parent dir named `tests` outside the project exempts nothing)", async (tool, input) => {
    expect(await decide(tool, input)).toBe("deny");
  });

  it("a fixture's content is still redacted before it reaches the model", async () => {
    const r = await handleClaudeCode(
      "post-tool-use",
      JSON.stringify({
        session_id: "w",
        cwd: proj,
        tool_name: "Bash",
        tool_input: { command: "cat testdata/.env" },
        tool_response: readFileSync(join(proj, "testdata", ".env"), "utf8"),
      }),
    );
    expect(r.stdout).not.toContain(FAKE.githubPat);
    expect(r.stdout).toMatch(/SECRETGATE_/);
  });
});

describe("Claude Code deny rules stay out of the fixtures' way", () => {
  it("ships no project-wide key-extension rule", () => {
    for (const rule of ["Read(**/*.pem)", "Read(**/*.key)", "Read(**/credentials.json)"]) expect(CC_DENY_RULES).not.toContain(rule);
  });

  it("re-installing removes the retired rules secretgate added — and only those", () => {
    const settingsPath = join(base, "settings.json");
    writeFileSync(settingsPath, JSON.stringify({ permissions: { deny: ["Read(**/*.pem)", "Read(**/*.key)", "Read(./mine)"] } }));
    writeFileSync(`${settingsPath}.secretgate-ownership.json`, JSON.stringify({ deny: ["Read(**/*.pem)", "Read(**/*.key)"] }));
    installClaudeCode({ settingsPath, command: "node x.mjs" });
    const deny: string[] = JSON.parse(readFileSync(settingsPath, "utf8")).permissions.deny;
    expect(deny).not.toContain("Read(**/*.pem)");
    expect(deny).not.toContain("Read(**/*.key)");
    expect(deny).toContain("Read(./mine)");
    expect(deny).toContain("Read(**/.env)");
    const owned: string[] = JSON.parse(readFileSync(`${settingsPath}.secretgate-ownership.json`, "utf8")).deny;
    expect(owned.every((r) => CC_DENY_RULES.includes(r))).toBe(true);
  });

  it("a pre-ownership (<= 1.4) install loses its retired rules too — seen on a real machine", () => {
    const legacy = [
      "Read(**/.env)",
      "Read(**/.env.local)",
      "Read(**/.env.*.local)",
      "Read(**/*.pem)",
      "Read(**/*.key)",
      "Read(**/id_rsa*)",
      "Read(**/id_ed25519*)",
      "Read(**/id_ecdsa*)",
      "Read(~/.aws/**)",
      "Read(**/.aws/**)",
      "Read(~/.ssh/**)",
      "Read(**/.ssh/**)",
      "Read(~/.kube/config)",
      "Read(**/.kube/config)",
      "Read(**/.netrc)",
      "Read(**/.npmrc)",
      "Read(**/.docker/config.json)",
      "Read(**/credentials.json)",
    ];
    const settingsPath = join(base, "legacy.json");
    writeFileSync(settingsPath, JSON.stringify({ permissions: { deny: legacy } }));
    installClaudeCode({ settingsPath, command: "node x.mjs" });
    const deny: string[] = JSON.parse(readFileSync(settingsPath, "utf8")).permissions.deny;
    for (const r of ["Read(**/*.pem)", "Read(**/*.key)", "Read(**/id_rsa*)", "Read(**/credentials.json)"]) expect(deny).not.toContain(r);
    expect(deny).toContain("Read(**/.env)");
  });

  it("a lone rule the user wrote themselves is never removed", () => {
    const settingsPath = join(base, "mine.json");
    writeFileSync(settingsPath, JSON.stringify({ permissions: { deny: ["Read(**/*.pem)"] } }));
    installClaudeCode({ settingsPath, command: "node x.mjs" });
    expect(JSON.parse(readFileSync(settingsPath, "utf8")).permissions.deny).toContain("Read(**/*.pem)");
  });
});

describe("another tool's hooks are never taken for secretgate's", () => {
  it("recognises only `hook <agent> <secretgate event>`", () => {
    expect(isSecretgateHook('node "/x/secretgate.mjs" hook codex pre-tool-use', "codex")).toBe(true);
    expect(isSecretgateHook("secretgate hook claude-code user-prompt-submit", "claude-code")).toBe(true);
    expect(isSecretgateHook("SCOPELET_CONFIG_DIR=/x /x/scopelet hook codex", "codex")).toBe(false);
    expect(isSecretgateHook("/x/scopelet hook claude-code", "claude-code")).toBe(false);
  });

  it("install keeps a foreign `hook codex` handler on the same event", () => {
    const codexDir = join(base, "codex");
    mkdirSync(codexDir, { recursive: true });
    writeFileSync(
      join(codexDir, "hooks.json"),
      JSON.stringify({ hooks: { PreToolUse: [{ matcher: ".*", hooks: [{ type: "command", command: "/x/scopelet hook codex" }] }] } }),
    );
    installCodex({ codexDir, command: "node x.mjs" });
    const hooks = JSON.parse(readFileSync(join(codexDir, "hooks.json"), "utf8")).hooks.PreToolUse.flatMap((g: { hooks: Array<{ command: string }> }) =>
      g.hooks.map((h) => h.command),
    );
    expect(hooks).toContain("/x/scopelet hook codex");
    expect(hooks).toContain("node x.mjs hook codex pre-tool-use");
  });
});
