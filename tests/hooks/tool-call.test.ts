import { describe, expect, it } from "vitest";
import { extractToolCall, patchPaths } from "../../src/hooks/tool-call.js";

describe("extractToolCall — one shape for every host", () => {
  it("Claude Code file tools", () => {
    expect(extractToolCall("Read", { file_path: "a.ts" })).toMatchObject({ kind: "read", paths: ["a.ts"] });
    expect(extractToolCall("NotebookRead", { notebook_path: "n.ipynb" })).toMatchObject({ kind: "read", paths: ["n.ipynb"] });
    expect(extractToolCall("NotebookEdit", { notebook_path: "n.ipynb" })).toMatchObject({ kind: "write", paths: ["n.ipynb"] });
    expect(extractToolCall("MultiEdit", { file_path: "a.ts", edits: [] })).toMatchObject({ kind: "write", paths: ["a.ts"] });
    expect(extractToolCall("LS", { path: "src" })).toMatchObject({ kind: "list", paths: ["src"] });
  });

  it("Glob's pattern is a file pattern; Grep's file filter is glob/include", () => {
    expect(extractToolCall("Glob", { pattern: "src/**/*.ts", path: "/p" })).toMatchObject({ kind: "search", searchRoot: "/p", pattern: "src/**/*.ts" });
    expect(extractToolCall("Grep", { pattern: "TODO", glob: "*.ts" })).toMatchObject({ kind: "search", pattern: "*.ts" });
    expect(extractToolCall("grep", { pattern: "TODO", include: "*.md" })).toMatchObject({ kind: "search", pattern: "*.md" });
  });

  it("Codex shells: Bash {command}, exec_command {cmd, workdir}, shell {command: []}", () => {
    expect(extractToolCall("Bash", { command: "ls" })).toMatchObject({ kind: "shell", command: "ls" });
    expect(extractToolCall("exec_command", { cmd: "ls", workdir: "src" })).toMatchObject({ kind: "shell", command: "ls", workdir: "src" });
    expect(extractToolCall("shell", { command: ["cat", "x"] })).toMatchObject({ kind: "shell", command: ["cat", "x"] });
    expect(extractToolCall("functions.exec_command", { cmd: "ls" })).toMatchObject({ kind: "shell" });
  });

  it("patches from Codex (command, raw string, shell heredoc) and OpenCode (patchText)", () => {
    const patch = "*** Begin Patch\n*** Update File: a.ts\n*** Move to: b.ts\n*** Delete File: c.ts\n*** End Patch";
    expect(extractToolCall("apply_patch", { command: patch }).paths).toEqual(["a.ts", "b.ts", "c.ts"]);
    expect(extractToolCall("apply_patch", patch).paths).toEqual(["a.ts", "b.ts", "c.ts"]);
    expect(extractToolCall("apply_patch", { patchText: patch }).kind).toBe("patch");
    expect(extractToolCall("shell", { command: ["apply_patch", patch] })).toMatchObject({ kind: "patch", paths: ["a.ts", "b.ts", "c.ts"] });
    expect(extractToolCall("exec_command", { cmd: `apply_patch <<'EOF'\n${patch}\nEOF` }).kind).toBe("patch");
  });

  it("MCP tools are classified by their own name", () => {
    expect(extractToolCall("mcp__filesystem__read_file", { path: "x" })).toMatchObject({ kind: "read", paths: ["x"] });
    expect(extractToolCall("mcp__jira__create_issue", { title: "x" })).toMatchObject({ kind: "other", paths: [] });
  });

  it("patchPaths ignores anything that is not a file header", () => {
    expect(patchPaths("+*** Add File: nope\n*** Add File: yes.txt")).toEqual(["yes.txt"]);
  });
});
