import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { CC_DENY_RULES, claudeCodeBatchHookWired, claudeCodeTakesBatchHook, installClaudeCode, uninstallClaudeCode } from "../../src/install/claude-code.js";
import { SettingsLinkError, SettingsParseError } from "../../src/install/json-merge.js";

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
  it("wires PostToolBatch, the only hook that sees a failed call's output, and removes it on uninstall", () => {
    installClaudeCode({ settingsPath, command, claudeVersion: "2.1.323 (Claude Code)" });
    const group = read().hooks.PostToolBatch;
    expect(group).toHaveLength(1);
    expect(group[0].matcher).toBeUndefined();
    expect(group[0].hooks[0].command).toBe(`${command} hook claude-code post-tool-batch`);
    expect(claudeCodeBatchHookWired(read())).toBe(true);
    // An install made before this hook existed is reported as incomplete.
    const older = read();
    delete older.hooks.PostToolBatch;
    expect(claudeCodeBatchHookWired(older)).toBe(false);
    uninstallClaudeCode({ settingsPath });
    expect(read().hooks).toBeUndefined();
  });

  // Claude Code before 2.1.101 ignores the WHOLE settings file when it names a
  // hook event it does not know (seen on 2.0.0: with PostToolBatch in the
  // file, no hook ran and a pasted token went to the model). The event is
  // written only for a Claude Code known to tolerate it.
  it("leaves PostToolBatch out for a Claude Code that would drop the whole file, or an unknown one", () => {
    for (const claudeVersion of [undefined, "", "2.0.0 (Claude Code)", "2.1.100", "1.0.128", "not a version"]) {
      installClaudeCode({ settingsPath, command, claudeVersion });
      expect(Object.keys(read().hooks).sort(), String(claudeVersion)).toEqual(["PostToolUse", "PreToolUse", "UserPromptSubmit"]);
      rmSync(settingsPath);
    }
    for (const claudeVersion of ["2.1.101", "2.1.263 (Claude Code)", "2.2.0", "3.0.1"]) {
      installClaudeCode({ settingsPath, command, claudeVersion });
      expect(Object.keys(read().hooks), claudeVersion).toContain("PostToolBatch");
      rmSync(settingsPath);
    }
    expect(claudeCodeTakesBatchHook("2.1.100")).toBe(false);
    expect(claudeCodeTakesBatchHook("2.1.101")).toBe(true);
  });

  // `claude --version` prints "2.1.323 (Claude Code)". Anything else is not
  // read for a number that happens to be in it: a wrapper that prints another
  // program's version first must not pass for a recent Claude Code.
  it("reads a version only in the shape Claude Code prints it; anything else is unknown", () => {
    for (const v of ["2.1.101 (Claude Code)", "2.1.101", " 2.2.0 (Claude Code)\n", "10.0.0", "2.1.1010 (Claude Code)"])
      expect(claudeCodeTakesBatchHook(v), v).toBe(true);
    for (const v of [
      "node v22.11.0\n2.1.323 (Claude Code)",
      "v22.11.0\n2.0.5 (Claude Code)",
      "Claude Code v2.10.0",
      "v2.1.323",
      "2.1.323 (Some Wrapper)",
      "2.1.101-beta.1",
      "02.001.0101",
      "1.2.3.4 2.1.200",
      "2.1.323 2.1.323",
      "2.1",
      "3",
    ])
      expect(claudeCodeTakesBatchHook(v), v).toBe(false);
  });

  it("removes PostToolBatch again when the install is re-run under an older Claude Code", () => {
    writeFileSync(settingsPath, JSON.stringify({ hooks: { PostToolBatch: [{ hooks: [{ type: "command", command: "/my/audit.sh" }] }] } }));
    installClaudeCode({ settingsPath, command, claudeVersion: "2.1.323" });
    expect(read().hooks.PostToolBatch).toHaveLength(2);
    installClaudeCode({ settingsPath, command, claudeVersion: "2.0.0" });
    // The user's own entry is theirs to keep; ours is gone.
    expect(read().hooks.PostToolBatch).toEqual([{ hooks: [{ type: "command", command: "/my/audit.sh" }] }]);
    expect(claudeCodeBatchHookWired(read())).toBe(false);
  });

  it("creates settings.json from scratch with its hook events + deny rules", () => {
    const r = installClaudeCode({ settingsPath, command });
    expect(r.changed).toBe(true);
    const s = read();
    expect(s.hooks.UserPromptSubmit[0].hooks[0].command).toBe(`${command} hook claude-code user-prompt-submit`);
    expect(s.hooks.PreToolUse[0].matcher).toBe("Read|Grep|Glob|LS|Edit|Write|MultiEdit|NotebookEdit|NotebookRead|Bash|mcp__.*");
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

// settings.json is the user's file: it can hold API keys in `env` behind 0600,
// and it is often a link into a dotfiles checkout.
describe("installClaudeCode — the file stays the user's", () => {
  const posix = process.platform !== "win32";

  it.runIf(posix)("keeps the permission bits of an existing settings.json", () => {
    writeFileSync(settingsPath, JSON.stringify({ env: { EXAMPLE: "1" } }));
    chmodSync(settingsPath, 0o600);
    installClaudeCode({ settingsPath, command });
    expect(statSync(settingsPath).mode & 0o777).toBe(0o600);
    uninstallClaudeCode({ settingsPath });
    expect(statSync(settingsPath).mode & 0o777).toBe(0o600);
  });

  it.runIf(posix)("writes through a symlinked settings.json instead of replacing the link", () => {
    mkdirSync(join(dir, "dotfiles", "claude"), { recursive: true });
    const real = join(dir, "dotfiles", "claude", "settings.json");
    writeFileSync(real, JSON.stringify({ env: { EXAMPLE: "1" } }));
    symlinkSync(real, settingsPath);
    installClaudeCode({ settingsPath, command });
    expect(lstatSync(settingsPath).isSymbolicLink()).toBe(true);
    expect(JSON.parse(readFileSync(real, "utf8")).hooks.PostToolUse).toHaveLength(1);
    uninstallClaudeCode({ settingsPath });
    expect(lstatSync(settingsPath).isSymbolicLink()).toBe(true);
    expect(JSON.parse(readFileSync(real, "utf8"))).toEqual({ env: { EXAMPLE: "1" } });
  });

  it("creates a new settings.json readable like any config file, and leaves no temp file", () => {
    installClaudeCode({ settingsPath, command });
    if (posix) expect(statSync(settingsPath).mode & 0o777).toBe(0o644);
    expect(readdirSync(dir).filter((f) => f.endsWith(".tmp"))).toEqual([]);
  });
});

// A repository can commit `.claude/settings.json` as a symlink. Writing
// through it is right for a link the file's owner made inside its own tree,
// and wrong for one that leads out of it: `init --project` would edit a file
// of another tool, somewhere in the user's home.
describe.runIf(process.platform !== "win32")("installClaudeCode — a link that leaves the project is refused", () => {
  let victim: string;
  let repo: string;
  let project: string;
  const victimText = '{"apiToken":"from-other-tool"}\n';

  beforeEach(() => {
    mkdirSync(join(dir, "home", "other-tool"), { recursive: true });
    victim = join(dir, "home", "other-tool", "config.json");
    writeFileSync(victim, victimText, { mode: 0o600 });
    repo = join(dir, "repo");
    project = join(repo, ".claude");
    mkdirSync(project, { recursive: true });
  });
  const untouched = () => {
    expect(readFileSync(victim, "utf8")).toBe(victimText);
    expect(readdirSync(join(dir, "home", "other-tool"))).toEqual(["config.json"]);
  };

  it("settings.json linked outside the project: nothing is written, copied or backed up", () => {
    symlinkSync(victim, join(project, "settings.json"));
    expect(() => installClaudeCode({ settingsPath: join(project, "settings.json"), command })).toThrow(SettingsLinkError);
    expect(() => uninstallClaudeCode({ settingsPath: join(project, "settings.json") })).toThrow(/outside/);
    untouched();
    // Not even a backup: it would copy the other tool's file into the repository.
    expect(readdirSync(project)).toEqual(["settings.json"]);
    expect(lstatSync(join(project, "settings.json")).isSymbolicLink()).toBe(true);
  });

  it("the ownership record linked outside the project: refused before settings.json changes", () => {
    writeFileSync(join(project, "settings.json"), "{}");
    symlinkSync(victim, join(project, "settings.json.secretgate-ownership.json"));
    expect(() => installClaudeCode({ settingsPath: join(project, "settings.json"), command })).toThrow(SettingsLinkError);
    expect(() => uninstallClaudeCode({ settingsPath: join(project, "settings.json") })).toThrow(SettingsLinkError);
    untouched();
    expect(readFileSync(join(project, "settings.json"), "utf8")).toBe("{}");
  });

  it("a `.claude` directory linked outside the project", () => {
    rmSync(project, { recursive: true });
    symlinkSync(join(dir, "home", "other-tool"), project);
    expect(() => installClaudeCode({ settingsPath: join(project, "settings.json"), command })).toThrow(SettingsLinkError);
    untouched();
  });

  it("a link that stays inside the project is written through, and `root` can name the tree", () => {
    mkdirSync(join(repo, "shared"));
    writeFileSync(join(repo, "shared", "settings.json"), "{}");
    symlinkSync(join(repo, "shared", "settings.json"), join(project, "settings.json"));
    installClaudeCode({ settingsPath: join(project, "settings.json"), command });
    expect(JSON.parse(readFileSync(join(repo, "shared", "settings.json"), "utf8")).hooks.PostToolUse).toHaveLength(1);
    // The same link is out of bounds for a narrower tree.
    expect(() => installClaudeCode({ settingsPath: join(project, "settings.json"), command, root: project })).toThrow(SettingsLinkError);
  });

  // Inside the project is not enough: `settings.json -> ../package.json`
  // stays in the tree, and the hooks would be written into package.json.
  // A link is followed only to a file that can be a settings file: one of
  // the same name, or one inside a directory named like the agent's own.
  it("a link to another kind of file inside the project is refused", () => {
    const pkg = '{"name":"x","version":"1.0.0"}\n';
    writeFileSync(join(repo, "package.json"), pkg);
    symlinkSync("../package.json", join(project, "settings.json"));
    expect(() => installClaudeCode({ settingsPath: join(project, "settings.json"), command })).toThrow(SettingsLinkError);
    expect(() => uninstallClaudeCode({ settingsPath: join(project, "settings.json") })).toThrow(SettingsLinkError);
    expect(readFileSync(join(repo, "package.json"), "utf8")).toBe(pkg);
    expect(readdirSync(repo).sort()).toEqual([".claude", "package.json"]);
    // …while a differently named file in a directory of the agent's kind is a settings file.
    rmSync(join(project, "settings.json"));
    mkdirSync(join(repo, "config", ".claude"), { recursive: true });
    writeFileSync(join(repo, "config", ".claude", "team.json"), "{}");
    symlinkSync(join(repo, "config", ".claude", "team.json"), join(project, "settings.json"));
    installClaudeCode({ settingsPath: join(project, "settings.json"), command });
    expect(JSON.parse(readFileSync(join(repo, "config", ".claude", "team.json"), "utf8")).hooks.PostToolUse).toHaveLength(1);
  });
});

describe("uninstallClaudeCode", () => {
  it("preserves a preexisting deny even when it is also one of our defaults", () => {
    writeFileSync(settingsPath, JSON.stringify({ permissions: { deny: [CC_DENY_RULES[0]] } }));
    installClaudeCode({ settingsPath, command });
    installClaudeCode({ settingsPath, command });
    uninstallClaudeCode({ settingsPath });
    expect(read().permissions.deny).toEqual([CC_DENY_RULES[0]]);
  });
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

// Everything secretgate <= 1.4 installed, before it recorded ownership.
const LEGACY = [
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

describe("uninstallClaudeCode — leaves nothing behind", () => {
  it("drops a hooks object it emptied", () => {
    writeFileSync(settingsPath, JSON.stringify({ theme: "dark" }));
    installClaudeCode({ settingsPath, command });
    uninstallClaudeCode({ settingsPath });
    expect(read()).toEqual({ theme: "dark" });
  });

  it("keeps a hooks object that still holds the user's hooks", () => {
    writeFileSync(settingsPath, JSON.stringify({ hooks: { Stop: [{ hooks: [{ type: "command", command: "/mine.sh" }] }] } }));
    installClaudeCode({ settingsPath, command });
    uninstallClaudeCode({ settingsPath });
    expect(read().hooks).toEqual({ Stop: [{ hooks: [{ type: "command", command: "/mine.sh" }] }] });
  });

  it("recognises a complete <= 1.4 deny set as its own when no ownership file exists", () => {
    writeFileSync(
      settingsPath,
      JSON.stringify({
        permissions: { deny: [...LEGACY, "Read(./mine/**)"] },
        hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: `${command} hook claude-code pre-tool-use` }] }] },
      }),
    );
    uninstallClaudeCode({ settingsPath });
    expect(read()).toEqual({ permissions: { deny: ["Read(./mine/**)"] } });
  });

  it("removes the <= 1.4 rules after an upgrade recorded ownership", () => {
    writeFileSync(settingsPath, JSON.stringify({ permissions: { deny: [...LEGACY, "Read(./mine/**)"] } }));
    installClaudeCode({ settingsPath, command });
    uninstallClaudeCode({ settingsPath });
    expect(read()).toEqual({ permissions: { deny: ["Read(./mine/**)"] } });
  });

  it("removes the <= 1.4 rules an earlier upgrade left out of its ownership record", () => {
    const kept = LEGACY.filter((r) => CC_DENY_RULES.includes(r));
    const addedLater = CC_DENY_RULES.filter((r) => !kept.includes(r));
    writeFileSync(settingsPath, JSON.stringify({ permissions: { deny: [...kept, ...addedLater, "Read(./mine/**)"] } }));
    writeFileSync(`${settingsPath}.secretgate-ownership.json`, JSON.stringify({ deny: addedLater }));
    uninstallClaudeCode({ settingsPath });
    expect(read()).toEqual({ permissions: { deny: ["Read(./mine/**)"] } });
  });

  it("keeps a single backup of its ownership file", () => {
    for (let i = 0; i < 3; i++) {
      // An ownership record from an older version: each install rewrites it.
      writeFileSync(`${settingsPath}.secretgate-ownership.json`, JSON.stringify({ deny: [`Read(old${i})`] }));
      installClaudeCode({ settingsPath, command });
    }
    expect(readdirSync(dir).filter((f) => f.includes("ownership.json.secretgate-backup-")).length).toBeLessThanOrEqual(1);
  });
});
