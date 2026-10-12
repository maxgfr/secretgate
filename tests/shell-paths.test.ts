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
    // The cd target itself is recorded as a listing: where the shell goes is checked too.
    expect(refs("cd private && cat notes.md")).toEqual(["list:private", "read:private/notes.md"]);
    expect(refs("(cd private; cat notes.md); cat README")).toEqual(["list:private", "read:private/notes.md", "read:README"]);
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
    expect(refs(["bash", "-lc", "cd private && cat notes.md"])).toEqual(["list:private", "read:private/notes.md"]);
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
    // A shell script given inline is analysed in place, not treated as opaque.
    expect(dyn("bash -c 'cat x'")).toEqual([]);
    expect(refs("bash -c 'cat private/notes.md'")).toEqual(["read:private/notes.md"]);
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
  it("expands lists, nested lists and bounded sequences; leaves unbalanced braces alone", () => {
    expect(expandBraces("a{b,c}d")).toEqual(["abd", "acd"]);
    expect(expandBraces("{a,b{c,d}}")).toEqual(["a", "bc", "bd"]);
    expect(expandBraces("x{1..3}")).toEqual(["x1", "x2", "x3"]);
    expect(expandBraces("{a..c}")).toEqual(["a", "b", "c"]);
    expect(expandBraces("{1..9..4}")).toEqual(["1", "5", "9"]);
    expect(expandBraces("{a..3}")).toEqual(["{a..3}"]);
    expect(expandBraces("x{")).toEqual(["x{"]);
  });
});

// Every case below is a reproduction from the v1.6.3 audit.
const names = (command: string | string[], cwd = dir) => analyzeShell(command, { cwd }).refs.map((r) => `${r.kind}:${r.path}`);
const has = (command: string | string[], expected: string, cwd = dir) => names(command, cwd).some((r) => r === expected || r.endsWith(expected));

describe("audit · tokenizer", () => {
  it("a heredoc delimiter ending its line still opens the heredoc", () => {
    expect(refs("cat <<E\nE\ncat private/notes.md")).toEqual(["read:private/notes.md"]);
  });

  it("a heredoc body is data, even when it looks like a command", () => {
    expect(refs("cat > doc.md <<EOF\ncat private/notes.md\nEOF")).toEqual(["write:doc.md"]);
  });

  it("$'…' stops at a NUL, like bash, and never yields an unresolved marker", () => {
    expect(refs("cat $'private/notes.md\\x00junk'")).toEqual(["read:private/notes.md"]);
    expect(refs("cat $'private/notes.md\\0junk'")).toEqual(["read:private/notes.md"]);
    expect(analyzeShell("cat $'README\\x00'", { cwd: dir }).dynamic).toEqual([]);
  });

  it("expands bounded brace sequences", () => {
    expect(refs("cat .e{m..o}v")).toEqual(["read:.env"]);
    expect(refs("cat src/{a..b}.ts")).toEqual(["read:src/a.ts", "read:src/b.ts"]);
  });

  it("a sequence past the expansion limit is dynamic, not silently truncated", () => {
    expect(analyzeShell("cat f{1..100000}", { cwd: dir }).dynamic).toContain("brace expansion past 256 words");
  });

  it("a quoted heredoc runs nothing; an unquoted one runs $(…) and backticks", () => {
    expect(refs("cat <<'EOF'\n$(cat private/notes.md)\nEOF")).toEqual([]);
    expect(refs("cat <<EOF\n`cat private/notes.md`\nEOF")).toEqual(["read:private/notes.md"]);
    expect(refs("cat <<EOF\n$(cat private/notes.md)\nEOF")).toEqual(["read:private/notes.md"]);
  });
});

describe("audit · wrappers and inline shells", () => {
  it.each([
    "sudo -u root cat private/notes.md",
    "sudo --user=root cat private/notes.md",
    "nice -n 5 cat private/notes.md",
    "timeout -k 1 5 cat private/notes.md",
    "timeout --signal KILL 5 cat private/notes.md",
    "env -u FOO cat private/notes.md",
    "doas cat private/notes.md",
    "doas -u root cat private/notes.md",
    "flock /tmp/lock cat private/notes.md",
    "watch -n 1 cat private/notes.md",
    "chrt 10 cat private/notes.md",
    "ionice -c 3 cat private/notes.md",
    "stdbuf -o L cat private/notes.md",
    "env -S 'cat private/notes.md'",
  ])("finds the command behind %j", (command) => {
    expect(refs(command)).toEqual(["read:private/notes.md"]);
  });

  it("env -C moves the working directory", () => {
    expect(refs("env -C private cat notes.md")).toEqual(["read:private/notes.md"]);
  });

  it("bash -o x -c SCRIPT: the script is the word after -c's options", () => {
    expect(refs("bash -o pipefail -c 'cat private/notes.md'")).toEqual(["read:private/notes.md"]);
    expect(refs("sh -ec 'cat private/notes.md'")).toEqual(["read:private/notes.md"]);
  });

  it("bash -c substitutes $0…$n from the arguments that follow", () => {
    expect(refs("bash -c 'cat $1' x private/notes.md")).toEqual(["read:private/notes.md"]);
    const braced = "$" + "{1}"; // `${1}`, without a template-looking literal
    expect(refs(`bash -c 'cat "${braced}" $2' x README private/notes.md`)).toEqual(["read:README", "read:private/notes.md"]);
    expect(refs("bash -c 'cat \"$@\"' x README private/notes.md")).toEqual(["read:README", "read:private/notes.md"]);
  });

  it("bash -c under an unknown cwd keeps it unknown", () => {
    const a = analyzeShell("cd $X && bash -c 'cat notes.md'", { cwd: dir });
    expect(a.unknownCwd).toBe(true);
    expect(a.refs.some((r) => r.path === join("/", "notes.md"))).toBe(false);
  });

  it("nesting depth accumulates through bash -c", () => {
    let command = "cat private/notes.md";
    for (let i = 0; i < 12; i++) command = `bash -c ${JSON.stringify(command)}`;
    expect(analyzeShell(command, { cwd: dir }).dynamic).toContain("nested substitution");
  });
});

describe("audit · git and searchers", () => {
  it("git global options are not the subcommand, and -C moves the cwd", () => {
    expect(refs("git --git-dir=.git show HEAD:private/notes.md")).toContain("read:private/notes.md");
    expect(refs("git --work-tree=. --git-dir .git show HEAD:private/notes.md")).toContain("read:private/notes.md");
    expect(refs("git -C private show HEAD:notes.md")).toContain("read:private/notes.md");
    expect(refs("git -c core.pager=cat diff")).toEqual(["search:."]);
  });

  it("the value of grep --include is not the pattern, and not a path", () => {
    expect(refs("grep -rn --include=*.ts foo src")).toEqual(["search:src"]);
    expect(refs("grep -rn --include '*.ts' foo src")).toEqual(["search:src"]);
    expect(refs("rg -n --glob '*.ts' foo src")).toEqual(["search:src"]);
  });
});

describe("audit · working directory", () => {
  it("a cd that may fail leaves both directories possible", () => {
    expect(has("cd nowhere; cat private/notes.md", `read:${join(dir, "private/notes.md")}`)).toBe(true);
    expect(has("cd private || cat README", `read:${join(dir, "README")}`)).toBe(true);
  });

  it("a cd in a pipeline or in the background does not move the shell", () => {
    expect(refs("cd private | true; cat README")).toContain("read:README");
    expect(refs("cd private & cat README")).toContain("read:README");
  });

  it("substitutions see the cwd of the command they belong to", () => {
    expect(refs("cd private && echo $(cat notes.md)")).toContain("read:private/notes.md");
    expect(refs("cd private && cat <(cat notes.md)")).toContain("read:private/notes.md");
  });

  it("an unresolvable word still yields a name-only reference", () => {
    const a = analyzeShell('cd "$(echo x)" && cat .env', { cwd: dir });
    expect(a.refs.some((r) => !r.explicit && r.path.endsWith(".env"))).toBe(true);
    expect(analyzeShell("cat ~root/.env", { cwd: dir }).refs.some((r) => !r.explicit && r.path.endsWith(".env"))).toBe(true);
    expect(analyzeShell("cat $X/.env", { cwd: dir }).refs.some((r) => !r.explicit && r.path.endsWith(".env"))).toBe(true);
  });
});

describe("audit · content reached another way", () => {
  it("a script handed to a shell on stdin is analysed", () => {
    expect(refs('bash <<< "cat private/notes.md"')).toEqual(["read:private/notes.md"]);
    expect(refs("sh <<EOF\ncat private/notes.md\nEOF")).toEqual(["read:private/notes.md"]);
  });

  it("interpreters read the files after an inline program", () => {
    expect(refs("perl -pe1 private/notes.md")).toEqual(["read:private/notes.md"]);
    expect(refs("ruby -ne 'print' private/notes.md")).toEqual(["read:private/notes.md"]);
    expect(refs("xargs -a private/notes.md echo")).toEqual(["read:private/notes.md"]);
  });

  it("an alias created in the command is followed to its source", () => {
    expect(refs("ln -s private/notes.md n.txt && cat n.txt")).toContain("read:private/notes.md");
    expect(refs("ln -s private/notes.md n.txt && cat n.txt").filter((r) => r === "read:private/notes.md").length).toBe(2);
  });
});

describe("audit · globs", () => {
  it("an invalid character class matches nothing instead of throwing", () => {
    expect(() => analyzeShell("ls [z-a]", { cwd: dir })).not.toThrow();
    expect(refs("ls [z-a]")).toEqual([]);
  });
});
