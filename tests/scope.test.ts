import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { loadConfig, type ScopeConfig, setTrust } from "../src/config.js";
import { extractToolCall } from "../src/hooks/tool-call.js";
import { accessViolation, filterSearchOutput, isControlFile, pathOutOfScope, promptScopeViolation, toolCallScopeViolation } from "../src/scope.js";

let root: string;
let home: string;

beforeEach(() => {
  root = realpathSync(mkdtempSync(join(tmpdir(), "secretgate-scope-")));
  home = mkdtempSync(join(tmpdir(), "secretgate-scope-home-"));
  process.env.SECRETGATE_HOME = home;
  mkdirSync(join(root, ".git"));
  for (const d of ["src/legacy", "src/app", "tests", "docs", "secret"]) mkdirSync(join(root, d), { recursive: true });
  for (const f of ["src/app/main.ts", "src/legacy/old.ts", "tests/a.test.ts", "docs/guide.md", "secret/plan.md", "package.json"])
    writeFileSync(join(root, f), "x\n");
});

afterEach(() => {
  delete process.env.SECRETGATE_HOME;
  rmSync(root, { recursive: true, force: true });
  rmSync(home, { recursive: true, force: true });
});

const scopeOf = (s: Partial<ScopeConfig>): ScopeConfig => ({ root, bash: "paths", file: join(root, ".secretgate.json"), ...s });
const std = () => scopeOf({ allow: ["src/**", "tests/**", "package.json"], deny: ["src/legacy/**"] });

describe("pathOutOfScope", () => {
  it("allows what allow matches, and nothing else", () => {
    const s = std();
    expect(pathOutOfScope(s, "src/app/main.ts", root)).toBeUndefined();
    expect(pathOutOfScope(s, "package.json", root)).toBeUndefined();
    expect(pathOutOfScope(s, "docs/guide.md", root)).toMatch(/not in scope\.allow/);
  });

  it("deny wins over allow", () => {
    expect(pathOutOfScope(std(), "src/legacy/old.ts", root)).toMatch(/scope\.deny 'src\/legacy\/\*\*'/);
  });

  it("a directory glob covers its descendants; dir/** also covers the dir itself", () => {
    const s = scopeOf({ allow: ["src"] });
    expect(pathOutOfScope(s, "src/app/main.ts", root)).toBeUndefined();
    expect(pathOutOfScope(std(), "src", root)).toBeUndefined();
  });

  it("supports {a,b} alternations", () => {
    const s = scopeOf({ allow: ["{src,tests}/**"] });
    expect(pathOutOfScope(s, "tests/a.test.ts", root)).toBeUndefined();
    expect(pathOutOfScope(s, "docs/guide.md", root)).toBeDefined();
  });

  it("resolves .. and ~ before matching", () => {
    expect(pathOutOfScope(std(), "src/../secret/plan.md", root)).toBeDefined();
    expect(pathOutOfScope(std(), "~/anything", root)).toMatch(/outside the project root/);
  });

  it("follows symlinks: an in-scope name pointing outside is out", () => {
    symlinkSync(join(root, "secret", "plan.md"), join(root, "src", "app", "link.md"));
    expect(pathOutOfScope(std(), "src/app/link.md", root)).toMatch(/secret\/plan\.md/);
  });

  it("anything outside the root is out once allow exists; absolute globs can let it in", () => {
    expect(pathOutOfScope(std(), "/etc/hosts", root)).toMatch(/outside the project root/);
    const withTmp = scopeOf({ allow: ["src/**", `${root}/docs/**`] });
    expect(pathOutOfScope(withTmp, join(root, "docs", "guide.md"), "/")).toBeUndefined();
  });

  it("deny-only scopes allow everything else", () => {
    const s = scopeOf({ deny: ["secret/**"] });
    expect(pathOutOfScope(s, "docs/guide.md", root)).toBeUndefined();
    expect(pathOutOfScope(s, "secret/plan.md", root)).toBeDefined();
    expect(pathOutOfScope(s, "/etc/hosts", root)).toBeUndefined();
  });

  it.runIf(process.platform === "darwin" || process.platform === "win32")("is case-insensitive where the filesystem is", () => {
    expect(pathOutOfScope(std(), "SRC/Legacy/old.ts", root)).toBeDefined();
    expect(pathOutOfScope(std(), "Src/app/main.ts", root)).toBeUndefined();
  });
});

describe("accessViolation — listings and searches", () => {
  it("listing an ancestor of allowed paths is fine; listing an unrelated dir is not", () => {
    expect(accessViolation(std(), ".", root, "list")).toBeUndefined();
    expect(accessViolation(std(), "docs", root, "list")).toBeDefined();
  });

  it("a recursive search needs every file below it in scope", () => {
    expect(accessViolation(std(), "src/app", root, "search")).toBeUndefined();
    expect(accessViolation(std(), "src", root, "search")).toMatch(/contains paths matching scope\.deny/);
    expect(accessViolation(std(), ".", root, "search")).toBeDefined();
  });
});

describe("toolCallScopeViolation", () => {
  const check = (tool: string, input: unknown, s = std()) => toolCallScopeViolation([s], extractToolCall(tool, input), root);

  it("Read/Write/Edit/NotebookEdit outside scope are denied", () => {
    expect(check("Read", { file_path: join(root, "docs/guide.md") })).toMatch(/secretgate scope/);
    expect(check("Read", { file_path: "src/app/main.ts" })).toBeUndefined();
    expect(check("Write", { file_path: "docs/new.md", content: "x" })).toBeDefined();
    expect(check("NotebookEdit", { notebook_path: "docs/n.ipynb" })).toBeDefined();
    expect(check("MultiEdit", { file_path: "src/legacy/old.ts", edits: [] })).toBeDefined();
  });

  it("Glob/Grep: denied on unrelated roots, allowed (then filtered) on ancestors", () => {
    expect(check("Glob", { pattern: "**/*.md", path: join(root, "docs") })).toBeDefined();
    expect(check("Grep", { pattern: "x", path: root })).toBeUndefined();
    expect(check("Glob", { pattern: "../**/*" })).toBeDefined();
    expect(check("Glob", { pattern: "/etc/*" })).toBeDefined();
  });

  it("Codex apply_patch and OpenCode patchText paths are checked", () => {
    const patch = "*** Begin Patch\n*** Update File: src/app/main.ts\n*** Add File: docs/x.md\n+x\n*** End Patch";
    expect(check("apply_patch", { command: patch })).toMatch(/docs\/x\.md/);
    expect(check("apply_patch", { patchText: patch })).toMatch(/docs\/x\.md/);
    expect(check("apply_patch", patch)).toMatch(/docs\/x\.md/);
  });

  it("Bash: every path of every command is checked", () => {
    expect(check("Bash", { command: "cat src/app/main.ts && cat docs/guide.md" })).toMatch(/docs\/guide\.md/);
    expect(check("Bash", { command: "cat src/app/main.ts" })).toBeUndefined();
    expect(check("Bash", { command: "cd secret && cat plan.md" })).toBeDefined();
    expect(check("Bash", { command: "pnpm test" })).toBeUndefined();
  });

  it("Codex exec_command {cmd} and shell {command: []} are checked", () => {
    expect(check("exec_command", { cmd: "cat docs/guide.md" })).toBeDefined();
    expect(check("shell", { command: ["cat", "docs/guide.md"] })).toBeDefined();
    expect(check("shell", { command: ["bash", "-lc", "cat docs/guide.md"] })).toBeDefined();
    expect(check("exec_command", { cmd: "cat main.ts", workdir: "src/app" })).toBeUndefined();
  });

  it("Bash: recursive reads of a partly out-of-scope tree are denied with advice", () => {
    const r = check("Bash", { command: "grep -rn TODO ." });
    expect(r).toMatch(/would read everything under/);
    expect(r).toMatch(/src\//);
    expect(check("Bash", { command: "rg TODO src/app tests" })).toBeUndefined();
    expect(check("Bash", { command: "git diff" })).toBeDefined();
    expect(check("Bash", { command: "git diff -- src/app" })).toBeUndefined();
    expect(check("Bash", { command: "git status" })).toBeUndefined();
  });

  it('Bash strict mode rejects what cannot be checked statically; "paths" lets it through', () => {
    const strict = scopeOf({ allow: ["src/**"], bash: "strict" });
    expect(check("Bash", { command: "cat $(echo src/app/main.ts)" }, strict)).toMatch(/strict/);
    expect(check("Bash", { command: "python3 -c 'print(1)'" }, strict)).toMatch(/strict/);
    expect(check("Bash", { command: "cat $(echo src/app/main.ts)" })).toBeUndefined();
  });

  it("policy files are read-only while a scope is active", () => {
    const s = scopeOf({ allow: ["**"] });
    expect(check("Write", { file_path: ".secretgate.json", content: "{}" }, s)).toMatch(/read-only/);
    expect(check("Write", { file_path: "src/.secretgate.json", content: "{}" }, s)).toMatch(/read-only/);
    expect(check("Edit", { file_path: ".claude/settings.local.json" }, s)).toMatch(/read-only/);
    expect(check("Bash", { command: "echo '{}' > .secretgate.json" }, s)).toMatch(/read-only/);
    expect(check("Bash", { command: "rm .secretgate.json" }, s)).toMatch(/read-only/);
    expect(check("Bash", { command: "cat .secretgate.json" }, s)).toBeUndefined();
    expect(check("Bash", { command: "node ~/.secretgate/bin/secretgate.mjs uninstall --all" }, s)).toMatch(/uninstall/);
    expect(isControlFile(s, join(home, "disabled.json"), root)).toBe(true);
  });
});

describe("filterSearchOutput", () => {
  it("drops out-of-scope files from Glob/Grep results of any shape", () => {
    const s = [std()];
    const glob = { filenames: [join(root, "src/app/main.ts"), join(root, "docs/guide.md")], numFiles: 2 };
    const r = filterSearchOutput(s, glob, root);
    expect(r.changed).toBe(true);
    expect(r.value).toEqual({ filenames: [join(root, "src/app/main.ts")], numFiles: 1 });
    const grep = `src/app/main.ts:1:x\ndocs/guide.md:1:x\nsecret/plan.md-2-x\n--\nFound 3 files`;
    expect(filterSearchOutput(s, grep, root).value).toBe("src/app/main.ts:1:x\n--\nFound 3 files");
  });

  it("drops OpenCode-style indented match lines under an out-of-scope header", () => {
    const text = `Found 2 matches\n${join(root, "docs/guide.md")}:\n  Line 1: x\n${join(root, "src/app/main.ts")}:\n  Line 1: x`;
    expect(filterSearchOutput([std()], text, root).value).toBe(`Found 2 matches\n${join(root, "src/app/main.ts")}:\n  Line 1: x`);
  });
});

describe("promptScopeViolation", () => {
  it("blocks @mentions of out-of-scope files, ignores emails and in-scope files", () => {
    expect(promptScopeViolation([std()], "look at @docs/guide.md please", root)).toMatch(/@docs\/guide\.md/);
    expect(promptScopeViolation([std()], "look at @src/app/main.ts", root)).toBeUndefined();
    expect(promptScopeViolation([std()], "mail me@docs.guide", root)).toBeUndefined();
    expect(promptScopeViolation([std()], "see @/etc/hosts", root)).toBeDefined();
  });
});

describe("loadConfig — project file lookup and validation", () => {
  it("finds .secretgate.json from a subdirectory, rooted where it lives", () => {
    writeFileSync(join(root, ".secretgate.json"), JSON.stringify({ scope: { allow: ["src/**"] } }));
    const cfg = loadConfig(join(root, "src", "app"));
    expect(cfg.scopes).toHaveLength(1);
    expect(cfg.scopes[0]!.root).toBe(root);
    expect(cfg.scopes[0]!.bash).toBe("paths");
  });

  it("applies every scope from cwd up to the repo root (a nested file cannot widen)", () => {
    writeFileSync(join(root, ".secretgate.json"), JSON.stringify({ scope: { allow: ["src/**"] } }));
    writeFileSync(join(root, "src", ".secretgate.json"), JSON.stringify({ allowlist: { rules: ["x"] } }));
    const cfg = loadConfig(join(root, "src"));
    expect(cfg.scopes).toHaveLength(1);
    // Untrusted: `scan` honors it, the hooks do not — until `secretgate trust`.
    expect(cfg.scanAllowlist.rules).toContain("x");
    expect(cfg.allowlist.rules).not.toContain("x");
    expect(cfg.untrusted).toEqual([join(root, "src", ".secretgate.json")]);
    setTrust([join(root, "src", ".secretgate.json")]);
    expect(loadConfig(join(root, "src")).allowlist.rules).toContain("x");
    // Editing the file revokes the trust.
    writeFileSync(join(root, "src", ".secretgate.json"), JSON.stringify({ allowlist: { rules: ["x", "y"] } }));
    expect(loadConfig(join(root, "src")).allowlist.rules).not.toContain("y");
  });

  it("treats a git worktree (`.git` is a file) as a repository root", () => {
    const outer = realpathSync(mkdtempSync(join(tmpdir(), "secretgate-wt-")));
    try {
      writeFileSync(join(outer, ".secretgate.json"), JSON.stringify({ scope: { allow: ["nothing/**"] } }));
      mkdirSync(join(outer, "wt", "src"), { recursive: true });
      writeFileSync(join(outer, "wt", ".git"), "gitdir: /elsewhere/.git/worktrees/wt\n");
      writeFileSync(join(outer, "wt", ".secretgate.json"), JSON.stringify({ scope: { allow: ["src/**"] } }));
      const cfg = loadConfig(join(outer, "wt", "src"));
      expect(cfg.scopes.map((s) => s.root)).toEqual([join(outer, "wt")]);
    } finally {
      rmSync(outer, { recursive: true, force: true });
    }
  });

  it("monorepo: a package scope and the root scope both apply (intersection)", () => {
    mkdirSync(join(root, "src", "app", "lib"), { recursive: true });
    writeFileSync(join(root, "src", "app", "lib", "x.ts"), "x\n");
    writeFileSync(join(root, ".secretgate.json"), JSON.stringify({ scope: { allow: ["src/**"] } }));
    writeFileSync(join(root, "src", "app", ".secretgate.json"), JSON.stringify({ scope: { allow: ["lib/**"] } }));
    const cwd = join(root, "src", "app");
    const cfg = loadConfig(cwd);
    expect(cfg.scopes).toHaveLength(2);
    const read = (p: string) => toolCallScopeViolation(cfg.scopes, extractToolCall("Read", { file_path: p }), cwd);
    expect(read("lib/x.ts")).toBeUndefined();
    expect(read("main.ts")).toMatch(/not in scope\.allow/); // allowed by the root, not by the package
    expect(read("../../tests/a.test.ts")).toBeDefined(); // allowed by neither
  });

  it("relative paths resolve from the agent's cwd, globs from each scope's root", () => {
    writeFileSync(join(root, ".secretgate.json"), JSON.stringify({ scope: { allow: ["src/**"] } }));
    const cwd = join(root, "src", "app");
    const cfg = loadConfig(cwd);
    const bash = (command: string) => toolCallScopeViolation(cfg.scopes, extractToolCall("Bash", { command }), cwd);
    expect(bash("cat main.ts")).toBeUndefined();
    expect(bash("cat ../legacy/old.ts")).toBeUndefined();
    expect(bash("cat ../../docs/guide.md")).toBeDefined();
    expect(bash("cd ../.. && cat package.json")).toBeDefined();
  });

  it("stops at the repository root", () => {
    const outer = realpathSync(mkdtempSync(join(tmpdir(), "secretgate-outer-")));
    try {
      writeFileSync(join(outer, ".secretgate.json"), JSON.stringify({ scope: { allow: ["nothing/**"] } }));
      mkdirSync(join(outer, "repo", ".git"), { recursive: true });
      expect(loadConfig(join(outer, "repo")).scopes).toHaveLength(0);
    } finally {
      rmSync(outer, { recursive: true, force: true });
    }
  });

  it("reports an invalid file instead of silently ignoring or mangling it", () => {
    writeFileSync(join(root, ".secretgate.json"), JSON.stringify({ allowlist: { paths: "tests/**" } }));
    expect(loadConfig(root).error?.message).toMatch(/allowlist\.paths must be an array/);
    expect(loadConfig(root).allowlist.paths).toEqual([]);
    writeFileSync(join(root, ".secretgate.json"), JSON.stringify({ scope: { allow: [""] } }));
    expect(loadConfig(root).error?.message).toMatch(/scope\.allow/);
    writeFileSync(join(root, ".secretgate.json"), JSON.stringify({ scope: { allow: ["src"], bash: "loose" } }));
    expect(loadConfig(root).error?.message).toMatch(/scope\.bash/);
    writeFileSync(join(root, ".secretgate.json"), "{ nope");
    expect(loadConfig(root).error?.message).toMatch(/JSON/);
  });

  it("ignores malformed global entries rather than spreading strings", () => {
    writeFileSync(join(home, "allowlist.json"), JSON.stringify({ paths: "tests/**", rules: ["ok", 3] }));
    const cfg = loadConfig(root);
    expect(cfg.allowlist.paths).toEqual([]);
    expect(cfg.allowlist.rules).toEqual(["ok"]);
  });
});
