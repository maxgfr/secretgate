import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { analyzeShell, expandBraces } from "../src/shell-paths.js";

let dir: string;

beforeAll(() => {
  dir = realpathSync(mkdtempSync(join(tmpdir(), "secretgate-sh-")));
  mkdirSync(join(dir, "src"));
  mkdirSync(join(dir, "private"));
  writeFileSync(join(dir, "src", "a.ts"), "");
  writeFileSync(join(dir, "src", "b.ts"), "");
  writeFileSync(join(dir, "private", "notes.md"), "");
  writeFileSync(join(dir, ".env"), "");
  writeFileSync(join(dir, "README"), "");
});

afterAll(() => rmSync(dir, { recursive: true, force: true }));

const refs = (command: string | string[]) =>
  analyzeShell(command, { cwd: dir })
    .refs.filter((r) => r.explicit)
    .map((r) => `${r.kind}:${r.path.startsWith(dir) ? r.path.slice(dir.length + 1) || "." : r.path}`);

describe("analyzeShell — words and quoting", () => {
  it("resolves plain, quoted and escaped arguments against the cwd", () => {
    expect(refs("cat src/a.ts 'private/notes.md' \"README\"")).toEqual(["read:src/a.ts", "read:private/notes.md", "read:README"]);
    expect(refs("cat private\\/notes.md")).toEqual(["read:private/notes.md"]);
  });

  it("follows every command of a pipeline / list, not just the first", () => {
    expect(refs("ls src && cat private/notes.md | grep x; head README")).toEqual(["list:src", "read:private/notes.md", "read:README"]);
  });

  it("tracks cd for the commands that follow, and restores it after a subshell", () => {
    expect(refs("cd private && cat notes.md")).toEqual(["read:private/notes.md"]);
    expect(refs("(cd private; cat notes.md); cat README")).toEqual(["read:private/notes.md", "read:README"]);
  });

  it("treats redirections as paths (read for <, write for >), ignoring fd dups and /dev/null", () => {
    expect(refs("wc -l < private/notes.md > out.txt 2>&1 2>/dev/null")).toEqual(["read:private/notes.md", "write:out.txt"]);
    expect(refs("cat<private/notes.md")).toEqual(["read:private/notes.md"]);
  });

  it("does not read heredoc bodies or here-strings as paths", () => {
    expect(refs("cat <<'EOF' > src/new.ts\nprivate/notes.md\nEOF\ncat README")).toEqual(["write:src/new.ts", "read:README"]);
    expect(refs("grep x <<< private/notes.md")).toEqual([]);
  });

  it("expands globs and brace lists against the filesystem (no dotglob)", () => {
    expect(refs("cat src/*.ts")).toEqual(["read:src/a.ts", "read:src/b.ts"]);
    expect(refs("cat .en*")).toEqual(["read:.env"]);
    expect(refs("cat {src/a.ts,private/notes.md}")).toEqual(["read:src/a.ts", "read:private/notes.md"]);
    expect(refs("cat *")).not.toContain("read:.env");
  });

  it("expands ~ and $HOME, and resolves .. lexically", () => {
    expect(analyzeShell("cat ~/x $HOME/y", { cwd: dir }).refs.map((r) => r.path)).toEqual([join(homedir(), "x"), join(homedir(), "y")]);
    expect(refs("cat src/../private/notes.md")).toEqual(["read:private/notes.md"]);
  });

  it("does not take bare words that name nothing on disk as certain paths", () => {
    const a = analyzeShell("git diff origin/main --stat", { cwd: dir });
    expect(a.refs.filter((r) => r.explicit)).toEqual([]);
  });

  it("skips arguments of commands that do not take files", () => {
    expect(refs("echo private/notes.md")).toEqual([]);
  });

  it("strips wrappers, assignments and keywords to find the real command", () => {
    expect(refs("FOO=1 sudo -u me cat private/notes.md")).toEqual(["read:private/notes.md"]);
    expect(refs("if true; then cat private/notes.md; fi")).toEqual(["read:private/notes.md"]);
  });

  it("accepts Codex argv arrays, unwrapping bash -lc scripts", () => {
    expect(refs(["cat", "private/notes.md"])).toEqual(["read:private/notes.md"]);
    expect(refs(["bash", "-lc", "cd private && cat notes.md"])).toEqual(["read:private/notes.md"]);
  });
});

describe("analyzeShell — searches", () => {
  it("recursive commands without a target search the working directory", () => {
    expect(refs("grep -rn TODO")).toEqual(["search:."]);
    expect(refs("rg TODO")).toEqual(["search:."]);
    expect(refs("find . -name '*.ts'")).toEqual(["search:."]);
    expect(refs("ls -R")).toEqual(["search:."]);
    expect(refs("tree")).toEqual(["search:."]);
  });

  it("the pattern of grep/rg is not a target, the rest are", () => {
    expect(refs("rg TODO src")).toEqual(["search:src"]);
    expect(refs("grep -r -e private src")).toEqual(["search:src"]);
    expect(refs("find src private -type f")).toEqual(["search:src", "search:private"]);
  });

  it("git content commands without a pathspec search the repository", () => {
    expect(refs("git diff")).toEqual(["search:."]);
    expect(refs("git show HEAD")).toEqual(["search:."]);
    expect(refs("git log -p")).toEqual(["search:."]);
    expect(refs("git diff HEAD~1 -- src")).toEqual(["search:src"]);
    expect(refs("git show HEAD:private/notes.md")).toEqual(["read:private/notes.md", "search:."]);
  });

  it("git commands that print names only are listings", () => {
    expect(refs("git diff --stat")).toEqual([]);
    expect(refs("git log --oneline")).toEqual([]);
    expect(refs("git status")).toEqual([]);
    expect(refs("git add src/a.ts")).toEqual(["list:src/a.ts"]);
  });

  it("plain ls lists the working directory", () => {
    expect(refs("ls")).toEqual(["list:."]);
    expect(refs("ls -la private")).toEqual(["list:private"]);
  });
});

describe("analyzeShell — what cannot be known statically", () => {
  it("flags substitutions, variables, eval and inline interpreters", () => {
    const dyn = (c: string) => analyzeShell(c, { cwd: dir }).dynamic;
    expect(dyn("cat $(echo private/notes.md)")).toContain("$(…)");
    expect(dyn("cat `echo x`")).toContain("`…`");
    expect(dyn("cat $FILE")).toContain("$FILE");
    expect(dyn("eval 'cat x'")).toContain("eval");
    expect(dyn("bash -c 'cat x'")).toContain("bash -c");
    expect(dyn("python3 -c 'print(open(\"x\").read())'")).toContain("python3 -c");
    expect(dyn("node -e 'x'")).toContain("node -e");
    expect(dyn("cat src/a.ts")).toEqual([]);
  });

  it("still analyses what a substitution runs", () => {
    expect(refs("echo $(cat private/notes.md)")).toEqual(["read:private/notes.md"]);
  });

  it("reports an unresolvable cd", () => {
    expect(analyzeShell("cd $X && cat notes.md", { cwd: dir }).unknownCwd).toBe(true);
  });
});

describe("expandBraces", () => {
  it("expands lists, nested lists, and leaves sequences/unbalanced braces alone", () => {
    expect(expandBraces("a{b,c}d")).toEqual(["abd", "acd"]);
    expect(expandBraces("{a,b{c,d}}")).toEqual(["a", "bc", "bd"]);
    expect(expandBraces("x{1..3}")).toEqual(["x{1..3}"]);
    expect(expandBraces("x{")).toEqual(["x{"]);
  });
});
