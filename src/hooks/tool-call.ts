// One view of a tool call for every host. Claude Code, Codex and OpenCode name
// their tools and arguments differently (`file_path` vs `filePath`, `Bash` vs
// `exec_command {cmd}` vs `shell {command: [...]}`, a patch in `command` vs
// `patchText`…). Policies — the sensitive-path deny and the scope — read this
// normalized shape, so a new host spelling is taught here once.

export type ToolKind = "read" | "write" | "search" | "list" | "shell" | "patch" | "other";

export interface NormalizedToolCall {
  kind: ToolKind;
  /** Files/directories the call names directly (as written; relative to cwd). */
  paths: string[];
  /** Shell command (string, or argv for Codex `shell`). */
  command?: string | string[];
  /** Codex `shell`/`exec_command` working directory, when the call sets one. */
  workdir?: string;
  /** Glob/Grep: the directory the search starts from (undefined → cwd). */
  searchRoot?: string;
  /** Glob: the pattern, which may itself carry a directory prefix. */
  pattern?: string;
}

const SHELL = new Set(["bash", "shell", "exec", "exec_command", "local_shell", "localshell", "run_command", "container.exec", "unified_exec"]);
const READ = new Set(["read", "read_file", "view", "open_file", "notebookread", "cat"]);
const WRITE = new Set(["write", "write_file", "create_file", "edit", "multiedit", "notebookedit", "str_replace", "str_replace_editor", "edit_file"]);
const PATCH = new Set(["apply_patch", "patch"]);
const LIST = new Set(["ls", "list", "list_dir", "list_directory"]);
const SEARCH_GLOB = new Set(["glob", "find_files", "file_search"]);
const SEARCH_GREP = new Set(["grep", "search", "search_files", "codesearch"]);

const str = (v: unknown): string | undefined => (typeof v === "string" && v.length > 0 ? v : undefined);

/** Paths a Codex/OpenCode patch touches (`*** Add File:`, `*** Move to:`…). */
export function patchPaths(patch: string): string[] {
  const out: string[] = [];
  for (const m of patch.matchAll(/^\*\*\* (?:Add File|Update File|Delete File|Move to): *(.+?) *$/gm)) out.push(m[1]!);
  return out;
}

function filePaths(input: Record<string, any>): string[] {
  const out: string[] = [];
  for (const key of ["file_path", "filePath", "path", "notebook_path", "notebookPath", "target_file", "file"]) {
    const v = str(input[key]);
    if (v) out.push(v);
  }
  for (const key of ["paths", "file_paths", "filePaths"]) {
    if (Array.isArray(input[key])) for (const v of input[key]) if (str(v)) out.push(v);
  }
  if (Array.isArray(input.edits))
    for (const e of input.edits) if (e && typeof e === "object" && str(e.file_path ?? e.filePath)) out.push(e.file_path ?? e.filePath);
  return [...new Set(out)];
}

function patchText(input: Record<string, any>): string | undefined {
  for (const key of ["patchText", "patch", "input", "command", "diff"]) {
    const v = input[key];
    if (typeof v === "string" && v.includes("*** ")) return v;
  }
  return undefined;
}

export function extractToolCall(toolName: string, toolInput: unknown): NormalizedToolCall {
  // `functions.exec_command` (Codex namespaces), `mcp__fs__read_file` (MCP).
  const name = toolName
    .toLowerCase()
    .replace(/^functions\./, "")
    .replace(/^mcp__.*__/, "");
  // Codex custom tools (apply_patch) may deliver the raw patch as the input.
  if (typeof toolInput === "string") {
    if (PATCH.has(name) || toolInput.startsWith("*** Begin Patch")) return { kind: "patch", paths: patchPaths(toolInput) };
    if (SHELL.has(name)) return { kind: "shell", paths: [], command: toolInput };
    return { kind: "other", paths: [] };
  }
  const input = (toolInput && typeof toolInput === "object" ? toolInput : {}) as Record<string, any>;

  if (PATCH.has(name)) {
    const patch = patchText(input);
    return { kind: "patch", paths: patch ? patchPaths(patch) : filePaths(input) };
  }
  if (SHELL.has(name)) {
    const cmd = input.cmd ?? input.command;
    // A patch can also arrive through the shell tool (`apply_patch <<EOF`).
    if (typeof cmd === "string" && /^\s*apply_patch\b/.test(cmd)) return { kind: "patch", paths: patchPaths(cmd) };
    if (Array.isArray(cmd) && cmd[0] === "apply_patch" && typeof cmd[1] === "string") return { kind: "patch", paths: patchPaths(cmd[1]) };
    const command = typeof cmd === "string" ? cmd : Array.isArray(cmd) ? cmd.map(String) : undefined;
    return { kind: "shell", paths: [], command, workdir: str(input.workdir) ?? str(input.cwd) };
  }
  if (READ.has(name)) return { kind: "read", paths: filePaths(input) };
  if (WRITE.has(name)) return { kind: "write", paths: filePaths(input) };
  if (LIST.has(name)) return { kind: "list", paths: filePaths(input) };
  if (SEARCH_GLOB.has(name) || SEARCH_GREP.has(name)) {
    const root = str(input.path) ?? str(input.directory) ?? str(input.dir);
    // Glob's `pattern` is a file pattern; Grep's is a content regex, and its
    // file filter is `glob` (Claude Code) / `include` (OpenCode).
    const pattern = SEARCH_GLOB.has(name) ? (str(input.pattern) ?? str(input.glob)) : (str(input.glob) ?? str(input.include));
    return { kind: "search", paths: root ? [root] : [], searchRoot: root, pattern };
  }
  // Unknown/MCP tools: still surface anything path-shaped they name.
  return { kind: "other", paths: filePaths(input) };
}
