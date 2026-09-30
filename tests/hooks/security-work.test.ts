import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { handleClaudeCode } from "../../src/hooks/claude-code.js";
import { CC_DENY_RULES, installClaudeCode } from "../../src/install/claude-code.js";
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
});
