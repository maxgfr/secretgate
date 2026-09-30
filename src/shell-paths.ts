import { lstatSync, readdirSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";

// Best-effort static analysis of a shell command: which paths does it read,
// write, list or search, and which parts cannot be known without running it.
// Shared by the sensitive-path deny and the scope check so both see the same
// words. It is a tokenizer, not a shell: it understands quoting, escapes,
// separators, redirections, heredocs, `cd`, globs and brace lists, and flags
// everything it cannot resolve statically ($VAR, $(…), eval, `sh -c`…) so the
// caller can decide how strict to be. The agent's own sandbox stays the hard
// boundary; this is the layer that keeps honest mistakes out of the model.

/** Marks an unresolvable expansion inside a word. Never a valid path byte. */
const DYN = "\u0000";

export interface ShellWord {
  /** Word after quote removal; DYN marks an unresolved expansion. */
  text: string;
  /** Contains an unquoted glob character (`*`, `?`, `[`). */
  glob: boolean;
  /** Contains an unquoted `{a,b}` list. */
  brace: boolean;
  /** The value of a `--flag=value` option, not a positional argument. */
  flagValue?: boolean;
}

interface Redirect {
  op: string;
  target: ShellWord;
}

interface SimpleCommand {
  words: ShellWord[];
  redirects: Redirect[];
  /** Fed by a heredoc or here-string. */
  stdinLiteral: boolean;
}

// read: content may be printed · write: created/changed · list: names or
// metadata only · search: everything below is read · exec: a script an
// interpreter runs (`node x.js`, `python y.py`).
export type PathRefKind = "read" | "write" | "list" | "search" | "exec";

export interface PathRef {
  /** Absolute, `~`-expanded, lexically resolved (not realpath'd). */
  path: string;
  kind: PathRefKind;
  /** The word as written (for messages). */
  raw: string;
  /** Command the path belongs to (basename). */
  command: string;
  /** Written as an explicit path (`/x`, `./x`, `~/x`, a redirection, a glob) or
   *  names something on disk. False for a bare word that may just as well be a
   *  ref or a message (`origin/main`): name-based checks (sensitive files)
   *  still look at those, existence-based ones (scope) skip them. */
  explicit: boolean;
  /** Came from a redirection (`< file`, `> file`), whatever the command. */
  redirect?: boolean;
}

export interface ShellAnalysis {
  refs: PathRef[];
  /** Every simple command, as argv after quote removal (DYN marks unknowns),
   *  including those run by substitutions. */
  commands: string[][];
  /** Constructs whose effect cannot be known statically — each a short label. */
  dynamic: string[];
  /** A relative path could not be resolved because `cd` went somewhere unknown. */
  unknownCwd: boolean;
}

// ---------------------------------------------------------------- tokenizer

interface ParseState {
  commands: SimpleCommand[];
  /** Sources of $(…), `…`, <(…), >(…) — analysed recursively. */
  substitutions: string[];
  dynamic: string[];
  /** Separator that preceded each command (`(`, `)` tracked for cwd scoping). */
  structure: Array<{ type: "cmd"; index: number } | { type: "open" } | { type: "close" } | { type: "pipe" }>;
}

const SEP_CHARS = new Set([";", "&", "|", "(", ")", "\n"]);

// Index just past the `)` that closes the construct opened at `start` (the
// char after `$(`). Tracks nesting and quotes; returns s.length when unclosed.
function matchParen(s: string, start: number): number {
  let depth = 1;
  let i = start;
  while (i < s.length) {
    const c = s[i];
    if (c === "\\") i += 2;
    else if (c === "'") {
      const end = s.indexOf("'", i + 1);
      i = end === -1 ? s.length : end + 1;
    } else if (c === '"') {
      i++;
      while (i < s.length && s[i] !== '"') i += s[i] === "\\" ? 2 : 1;
      i++;
    } else if (c === "(") {
      depth++;
      i++;
    } else if (c === ")") {
      if (--depth === 0) return i + 1;
      i++;
    } else i++;
  }
  return s.length;
}

function matchBacktick(s: string, start: number): number {
  let i = start;
  while (i < s.length && s[i] !== "`") i += s[i] === "\\" ? 2 : 1;
  return Math.min(i + 1, s.length);
}

// Commands run from inside an arithmetic expression: `$(( $(cat x) ))`.
function innerSubstitutions(text: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < text.length; i++) {
    if (text[i] === "$" && text[i + 1] === "(" && text[i + 2] !== "(") {
      const end = matchParen(text, i + 2);
      out.push(text.slice(i + 2, end - 1));
      i = end - 1;
    } else if (text[i] === "`") {
      const end = matchBacktick(text, i + 1);
      out.push(text.slice(i + 1, end - 1));
      i = end - 1;
    }
  }
  return out;
}

const ANSI_ESCAPES: Record<string, string> = {
  n: "\n",
  t: "\t",
  r: "\r",
  a: "\x07",
  b: "\b",
  e: "\x1b",
  E: "\x1b",
  f: "\f",
  v: "\v",
  "\\": "\\",
  "'": "'",
  '"': '"',
  "?": "?",
};

// Decode `$'…'` starting after the opening quote.
function ansiC(s: string, start: number): { text: string; end: number } {
  let text = "";
  let i = start;
  while (i < s.length && s[i] !== "'") {
    if (s[i] !== "\\") {
      text += s[i];
      i++;
      continue;
    }
    const n = s[i + 1] ?? "";
    const hex = /^x([0-9a-fA-F]{1,2})/.exec(s.slice(i + 1));
    const uni = /^[uU]([0-9a-fA-F]{1,8})/.exec(s.slice(i + 1));
    const oct = /^([0-7]{1,3})/.exec(s.slice(i + 1));
    if (hex) {
      text += String.fromCharCode(Number.parseInt(hex[1]!, 16));
      i += 1 + hex[0].length;
    } else if (uni) {
      text += String.fromCodePoint(Math.min(Number.parseInt(uni[1]!, 16), 0x10ffff));
      i += 1 + uni[0].length;
    } else if (oct) {
      text += String.fromCharCode(Number.parseInt(oct[1]!, 8));
      i += 1 + oct[0].length;
    } else {
      text += ANSI_ESCAPES[n] ?? n;
      i += 2;
    }
  }
  return { text, end: Math.min(i + 1, s.length) };
}

const VAR_RE = /^[A-Za-z_][A-Za-z0-9_]*/;

function tokenize(command: string, cwd: string): ParseState {
  const st: ParseState = { commands: [], substitutions: [], dynamic: [], structure: [] };
  let cur: SimpleCommand = { words: [], redirects: [], stdinLiteral: false };
  let word = "";
  let inWord = false;
  let glob = false;
  let brace = false;
  let pendingRedirect: string | undefined;
  const heredocs: Array<{ delim: string; strip: boolean }> = [];
  let i = 0;

  const endWord = (): void => {
    if (!inWord) return;
    const w: ShellWord = { text: word, glob, brace };
    if (pendingRedirect) {
      cur.redirects.push({ op: pendingRedirect, target: w });
      if (pendingRedirect === "<<" || pendingRedirect === "<<-") {
        heredocs.push({ delim: word.replaceAll(DYN, ""), strip: pendingRedirect === "<<-" });
        cur.stdinLiteral = true;
      }
      if (pendingRedirect === "<<<") cur.stdinLiteral = true;
      pendingRedirect = undefined;
    } else cur.words.push(w);
    word = "";
    inWord = false;
    glob = false;
    brace = false;
  };
  const endCommand = (): void => {
    endWord();
    if (cur.words.length > 0 || cur.redirects.length > 0) {
      st.structure.push({ type: "cmd", index: st.commands.length });
      st.commands.push(cur);
    }
    cur = { words: [], redirects: [], stdinLiteral: false };
  };
  const expandVar = (name: string): string => {
    if (name === "HOME") return homedir();
    if (name === "PWD") return cwd;
    st.dynamic.push(`$${name}`);
    return DYN;
  };

  while (i < command.length) {
    const c = command[i]!;
    // Heredoc bodies start on the line after their `<<DELIM` and are data.
    if (c === "\n" && heredocs.length > 0) {
      endCommand();
      i++;
      for (const { delim, strip } of heredocs.splice(0)) {
        for (;;) {
          const nl = command.indexOf("\n", i);
          const line = command.slice(i, nl === -1 ? command.length : nl);
          i = nl === -1 ? command.length : nl + 1;
          if ((strip ? line.replace(/^\t+/, "") : line) === delim || nl === -1) break;
          // An unquoted body still runs $(…) — keep analysing those.
          for (const m of line.matchAll(/\$\(/g)) st.substitutions.push(line.slice(m.index + 2, matchParen(line, m.index + 2) - 1));
        }
      }
      continue;
    }
    if (c === " " || c === "\t") {
      endWord();
      i++;
    } else if (c === "#" && !inWord) {
      const nl = command.indexOf("\n", i);
      i = nl === -1 ? command.length : nl;
    } else if (c === "\\") {
      if (command[i + 1] === "\n") {
        i += 2;
      } else {
        word += command[i + 1] ?? "";
        inWord = true;
        i += 2;
      }
    } else if (c === "'") {
      const end = command.indexOf("'", i + 1);
      word += command.slice(i + 1, end === -1 ? command.length : end);
      inWord = true;
      i = end === -1 ? command.length : end + 1;
    } else if (c === '"') {
      inWord = true;
      i++;
      while (i < command.length && command[i] !== '"') {
        const d = command[i]!;
        if (d === "\\" && i + 1 < command.length && '"\\$`\n'.includes(command[i + 1]!)) {
          if (command[i + 1] !== "\n") word += command[i + 1];
          i += 2;
        } else if (d === "$" && command[i + 1] === "(") {
          const end = matchParen(command, i + 2);
          st.substitutions.push(command.slice(i + 2, end - 1));
          st.dynamic.push("$(…)");
          word += DYN;
          i = end;
        } else if (d === "`") {
          const end = matchBacktick(command, i + 1);
          st.substitutions.push(command.slice(i + 1, end - 1));
          st.dynamic.push("`…`");
          word += DYN;
          i = end;
        } else if (d === "$" && command[i + 1] === "{") {
          const end = command.indexOf("}", i);
          word += expandVar(command.slice(i + 2, end === -1 ? command.length : end));
          i = end === -1 ? command.length : end + 1;
        } else if (d === "$" && VAR_RE.test(command.slice(i + 1))) {
          const name = VAR_RE.exec(command.slice(i + 1))![0];
          word += expandVar(name);
          i += 1 + name.length;
        } else {
          word += d;
          i++;
        }
      }
      i++;
    } else if (c === "$" && command[i + 1] === "'") {
      // ANSI-C quoting: `$'.env'`, `$'\x2eenv'` — decode, it is a literal.
      const { text, end } = ansiC(command, i + 2);
      word += text;
      inWord = true;
      i = end;
    } else if (c === "$" && command[i + 1] === '"') {
      // Locale quoting `$"…"` behaves like "…".
      i++;
    } else if (c === "$" && command[i + 1] === "(") {
      const arithmetic = command[i + 2] === "(";
      const end = matchParen(command, i + 2);
      if (!arithmetic) st.substitutions.push(command.slice(i + 2, end - 1));
      else st.substitutions.push(...innerSubstitutions(command.slice(i + 3, end - 2)));
      st.dynamic.push(arithmetic ? "$((…))" : "$(…)");
      word += DYN;
      inWord = true;
      i = end;
    } else if (c === "$" && command[i + 1] === "{") {
      const end = command.indexOf("}", i);
      word += expandVar(command.slice(i + 2, end === -1 ? command.length : end));
      inWord = true;
      i = end === -1 ? command.length : end + 1;
    } else if (c === "$" && VAR_RE.test(command.slice(i + 1))) {
      const name = VAR_RE.exec(command.slice(i + 1))![0];
      word += expandVar(name);
      inWord = true;
      i += 1 + name.length;
    } else if (c === "$" && /^[0-9@*#?$!-]/.test(command[i + 1] ?? "")) {
      st.dynamic.push(`$${command[i + 1]}`);
      word += DYN;
      inWord = true;
      i += 2;
    } else if (c === "`") {
      const end = matchBacktick(command, i + 1);
      st.substitutions.push(command.slice(i + 1, end - 1));
      st.dynamic.push("`…`");
      word += DYN;
      inWord = true;
      i = end;
    } else if ((c === "<" || c === ">") && command[i + 1] === "(") {
      // Process substitution: the inner command runs; the word is a pipe path.
      endWord();
      const end = matchParen(command, i + 2);
      st.substitutions.push(command.slice(i + 2, end - 1));
      i = end;
    } else if (c === "<" || c === ">" || (c === "&" && command[i + 1] === ">")) {
      // A redirection. A pure-digit word right before it is its fd number.
      if (inWord && /^\d+$/.test(word)) {
        word = "";
        inWord = false;
      }
      endWord();
      const op = /^(?:&>>|&>|<<<|<<-|<<|>>|>\||>&|<&|<>|<|>)/.exec(command.slice(i))![0];
      i += op.length;
      // `2>&1`, `>&-`: fd duplication, not a path.
      if ((op === ">&" || op === "<&") && /^\s*(?:\d+|-)(?=\s|$|[;&|)])/.test(command.slice(i))) {
        i += /^\s*(?:\d+|-)/.exec(command.slice(i))![0].length;
        continue;
      }
      pendingRedirect = op === ">&" ? ">" : op === "<&" ? "<" : op;
    } else if (c === "(" && command[i + 1] === "(" && !inWord && cur.words.length === 0) {
      // `(( n = 1 << 2 ))` is arithmetic, not a subshell with a heredoc.
      endCommand();
      const end = matchParen(command, i + 1);
      st.substitutions.push(...innerSubstitutions(command.slice(i + 2, Math.max(i + 2, end - 2))));
      i = end;
    } else if (SEP_CHARS.has(c)) {
      endCommand();
      if (c === "(") st.structure.push({ type: "open" });
      else if (c === ")") st.structure.push({ type: "close" });
      else if (c === "|" && command[i + 1] !== "|") st.structure.push({ type: "pipe" });
      // `&&`, `||`, `;;` are one separator.
      i += (c === "&" || c === "|" || c === ";") && command[i + 1] === c ? 2 : 1;
    } else {
      if (c === "*" || c === "?" || c === "[") glob = true;
      if (c === "{") brace = true;
      word += c;
      inWord = true;
      i++;
    }
  }
  endCommand();
  return st;
}

// ---------------------------------------------------------------- expansion

/** `{a,b}c` → [ac, bc]. Sequences (`{1..3}`) and unbalanced braces stay literal. */
export function expandBraces(text: string, limit = 256): string[] {
  const open = text.indexOf("{");
  if (open === -1) return [text];
  let depth = 0;
  const commas: number[] = [];
  let close = -1;
  for (let i = open; i < text.length; i++) {
    const c = text[i];
    if (c === "{") depth++;
    else if (c === "}" && --depth === 0) {
      close = i;
      break;
    } else if (c === "," && depth === 1) commas.push(i);
  }
  if (close === -1) return [text];
  const head = text.slice(0, open);
  const tail = text.slice(close + 1);
  if (commas.length === 0) return expandBraces(tail, limit).map((t) => `${text.slice(0, close + 1)}${t}`);
  const bounds = [open, ...commas, close];
  const out: string[] = [];
  for (let k = 0; k + 1 < bounds.length; k++) {
    for (const t of expandBraces(`${head}${text.slice(bounds[k]! + 1, bounds[k + 1])}${tail}`, limit)) {
      out.push(t);
      if (out.length >= limit) return out;
    }
  }
  return out;
}

function segmentRegex(segment: string): RegExp {
  let re = "";
  for (let i = 0; i < segment.length; i++) {
    const c = segment[i]!;
    if (c === "*") re += "[^/]*";
    else if (c === "?") re += "[^/]";
    else if (c === "[") {
      const end = segment.indexOf("]", i + 2);
      if (end === -1) re += "\\[";
      else {
        re += `[${segment
          .slice(i + 1, end)
          .replace(/^!/, "^")
          .replaceAll("\\", "\\\\")}]`;
        i = end;
      }
    } else re += c.replace(/[.+^${}()|\\]/g, "\\$&");
  }
  return new RegExp(`^${re}$`);
}

const GLOB_LIMIT = 2000;

/** Expand a shell glob against the filesystem, bash-style (no dotglob:
 *  `*` never matches a leading `.`). `overflow` when too many matches. */
function expandGlob(absPattern: string): { matches: string[]; overflow: boolean } {
  const parts = absPattern.split("/").filter((p, idx) => p !== "" || idx === 0);
  let frontier = [parts[0] === "" ? "/" : parts[0]!];
  for (const part of parts.slice(1)) {
    const next: string[] = [];
    const isGlob = /[*?[]/.test(part);
    const re = isGlob ? segmentRegex(part.replaceAll("**", "*")) : undefined;
    for (const dir of frontier) {
      if (!re) {
        next.push(join(dir, part));
        continue;
      }
      let entries: string[];
      try {
        entries = readdirSync(dir);
      } catch {
        continue;
      }
      for (const name of entries) {
        if (name.startsWith(".") && !part.startsWith(".")) continue;
        if (re.test(name)) next.push(join(dir, name));
        if (next.length > GLOB_LIMIT) return { matches: [], overflow: true };
      }
    }
    frontier = next;
  }
  return { matches: frontier.filter((p) => exists(p)), overflow: false };
}

function exists(p: string): boolean {
  try {
    lstatSync(p);
    return true;
  } catch {
    return false;
  }
}

export function expandHome(p: string): string {
  if (p === "~") return homedir();
  if (p.startsWith("~/")) return join(homedir(), p.slice(2));
  return p;
}

// ---------------------------------------------------------------- semantics

// Wrappers whose real command follows (flags/assignments skipped).
const WRAPPERS = new Set(["sudo", "env", "time", "nice", "nohup", "command", "builtin", "exec", "timeout", "stdbuf", "ionice", "caffeinate"]);
// Commands whose arguments are not file paths (only redirections matter).
const NON_PATH_ARGS = new Set([
  "echo",
  "printf",
  "print",
  "export",
  "alias",
  "unalias",
  "true",
  "false",
  "sleep",
  "kill",
  "exit",
  "return",
  "set",
  "unset",
  "read",
  "type",
  "which",
  "hash",
  "jobs",
  "wait",
  "shift",
  "trap",
  "ulimit",
  "umask",
  "history",
]);
// Commands whose path arguments are written/touched, never printed.
const WRITE_ARGS = new Set(["touch", "mkdir", "rm", "rmdir", "tee", "truncate", "chmod", "chown", "chgrp", "unlink", "shred"]);
// Commands that only print names/metadata of their arguments.
const LIST_ARGS = new Set(["ls", "dir", "stat", "file", "test", "[", "[[", "wc", "realpath", "readlink", "basename", "dirname"]);
// Interpreters: in strict mode, inline programs and stdin programs are opaque.
const INTERPRETERS = /^(?:bash|sh|zsh|dash|ksh|fish|python[0-9.]*|node|nodejs|deno|bun|perl|ruby|php|lua|osascript|pwsh|powershell)$/;
const INLINE_FLAGS = new Set(["-c", "-e", "-p", "-r", "--eval", "--print", "-E", "eval", "-Command"]);
const SHELLS = /^(?:bash|sh|zsh|dash|ksh)$/;
const EVAL_COMMANDS = new Set(["eval", "source", ".", "xargs", "parallel", "watch"]);

interface CommandShape {
  cmd: string;
  /** Positional args (flags removed, values of `--x=v` kept as their own args). */
  args: string[];
  argWords: ShellWord[];
  flags: string[];
}

const KEYWORDS = new Set(["if", "then", "else", "elif", "fi", "do", "done", "while", "until", "!", "{", "}"]);

// Index of the word that names the command: leading assignments (`FOO=bar`),
// shell keywords (`then`, `do`, `!`) and wrappers (`sudo -u x`) are skipped.
function commandIndex(words: ShellWord[]): number {
  let k = 0;
  for (;;) {
    while (k < words.length && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(words[k]!.text) || KEYWORDS.has(words[k]!.text))) k++;
    if (k >= words.length || !WRAPPERS.has(basename(words[k]!.text))) return k;
    const wrapper = basename(words[k]!.text);
    k++;
    while (k < words.length && (words[k]!.text.startsWith("-") || /^[A-Za-z_][A-Za-z0-9_]*=/.test(words[k]!.text))) k++;
    if (wrapper === "timeout" && k < words.length && /^\d/.test(words[k]!.text)) k++;
  }
}

function shapeOf(words: ShellWord[]): CommandShape | undefined {
  const k = commandIndex(words);
  if (k >= words.length) return undefined;
  const cmd = basename(words[k]!.text);
  const args: string[] = [];
  const argWords: ShellWord[] = [];
  const flags: string[] = [];
  let endOfFlags = false;
  for (const w of words.slice(k + 1)) {
    if (!endOfFlags && w.text === "--") {
      endOfFlags = true;
      flags.push("--");
      continue;
    }
    if (!endOfFlags && w.text.startsWith("-") && w.text.length > 1) {
      flags.push(w.text);
      const eq = w.text.indexOf("=");
      if (w.text.startsWith("--") && eq > 0) {
        args.push(w.text.slice(eq + 1));
        argWords.push({ ...w, text: w.text.slice(eq + 1), flagValue: true });
      }
      continue;
    }
    args.push(w.text);
    argWords.push(w);
  }
  return { cmd, args, argWords, flags };
}

const hasFlag = (flags: string[], short: string[], long: string[]): boolean =>
  flags.some((f) => long.includes(f.split("=")[0]!) || (/^-[A-Za-z]+$/.test(f) && short.some((s) => f.includes(s))));

// Flags that take a value in the next word, per command — so the value is not
// mistaken for a positional path (`grep -e PATTERN`, `head -n 5`).
const VALUE_FLAGS: Record<string, string[]> = {
  grep: ["-e", "-f", "-m", "-A", "-B", "-C", "--include", "--exclude", "--exclude-dir"],
  rg: ["-e", "-f", "-g", "-t", "-T", "-m", "-A", "-B", "-C", "--glob", "--type", "--max-count"],
  head: ["-n", "-c"],
  tail: ["-n", "-c"],
  sed: ["-e", "-f"],
  awk: ["-f", "-v", "-F"],
  find: [],
  git: ["-C", "-c"],
  // Output files: `openssl genrsa -out server.key` writes, it does not read.
  openssl: ["-out", "-passout"],
};

/** Positional args with the values of known value-taking flags removed;
 *  `--opt=value` contributes its value. `dashAt` is the index in `pos` where a
 *  `--` separator appeared (-1 when none). */
function positionals(words: ShellWord[], cmd: string): { pos: ShellWord[]; dashAt: number } {
  const valued = new Set(VALUE_FLAGS[cmd] ?? []);
  const pos: ShellWord[] = [];
  let dashAt = -1;
  for (let j = commandIndex(words) + 1; j < words.length; j++) {
    const w = words[j]!;
    const t = w.text;
    if (dashAt === -1 && t === "--") {
      dashAt = pos.length;
      continue;
    }
    if (dashAt === -1 && t.startsWith("-") && t.length > 1) {
      const eq = t.indexOf("=");
      if (t.startsWith("--") && eq > 0) pos.push({ ...w, text: t.slice(eq + 1), flagValue: true });
      else if (valued.has(t)) j++;
      continue;
    }
    pos.push(w);
  }
  return { pos, dashAt };
}

function explicitPath(text: string): boolean {
  return text.startsWith("/") || text.startsWith("~") || text.startsWith("./") || text.startsWith("../") || text === "." || text === "..";
}

export interface AnalyzeOptions {
  cwd: string;
}

/** Analyse a shell command (string, or Codex-style argv array). */
export function analyzeShell(command: string | string[], opts: AnalyzeOptions): ShellAnalysis {
  const out: ShellAnalysis = { refs: [], commands: [], dynamic: [], unknownCwd: false };
  if (Array.isArray(command)) {
    // Codex `shell` passes argv; `["bash","-lc","<script>"]` is the usual shape.
    const [bin, flag, script] = command;
    if (command.length === 3 && typeof bin === "string" && INTERPRETERS.test(basename(bin)) && /^-[a-z]*c$/.test(String(flag)) && typeof script === "string") {
      return analyzeShell(script, opts);
    }
    return analyzeShell(command.map(quoteArg).join(" "), opts);
  }
  analyzeInto(command, opts.cwd, out, 0);
  out.dynamic = [...new Set(out.dynamic)];
  return out;
}

function quoteArg(a: unknown): string {
  return `'${String(a).replaceAll("'", `'\\''`)}'`;
}

function analyzeInto(command: string, startCwd: string, out: ShellAnalysis, depth: number): void {
  if (depth > 8) {
    out.dynamic.push("nested substitution");
    return;
  }
  const st = tokenize(command, startCwd);
  out.dynamic.push(...st.dynamic);
  for (const sub of st.substitutions) analyzeInto(sub, startCwd, out, depth + 1);

  let cwd: string | undefined = startCwd;
  const stack: Array<string | undefined> = [];
  let inPipeline = false;
  for (const node of st.structure) {
    if (node.type === "open") {
      stack.push(cwd);
      continue;
    }
    if (node.type === "close") {
      cwd = stack.length > 0 ? stack.pop() : cwd;
      continue;
    }
    if (node.type === "pipe") {
      inPipeline = true;
      continue;
    }
    const sc = st.commands[node.index]!;
    const next = analyzeCommand(sc, cwd, out, inPipeline);
    inPipeline = false;
    cwd = next;
  }
}

function resolveWord(w: ShellWord, cwd: string | undefined, out: ShellAnalysis): string[] | undefined {
  if (w.text.includes(DYN)) return undefined;
  const variants = w.brace ? expandBraces(w.text) : [w.text];
  const paths: string[] = [];
  for (const v of variants) {
    // `~+` is $PWD; `~-` ($OLDPWD) and `~user` cannot be resolved here.
    if (/^~\+(?:\/|$)/.test(v) && cwd !== undefined) {
      paths.push(resolve(cwd, `.${v.slice(2)}`));
      continue;
    }
    if (/^~[^/]/.test(v)) {
      out.dynamic.push(v.split("/")[0]!);
      out.unknownCwd = true;
      return undefined;
    }
    const expanded = expandHome(v);
    if (!isAbsolute(expanded) && cwd === undefined) {
      out.unknownCwd = true;
      return undefined;
    }
    const abs = resolve(cwd ?? "/", expanded);
    if (w.glob && /[*?[]/.test(v)) {
      const g = expandGlob(abs);
      if (g.overflow) {
        // Too many matches: treat as a search of the glob's static prefix.
        paths.push(`${DYN}search:${staticPrefixDir(abs)}`);
      } else paths.push(...g.matches);
    } else paths.push(abs);
  }
  return paths;
}

function staticPrefixDir(abs: string): string {
  const idx = abs.search(/[*?[]/);
  return idx === -1 ? abs : dirname(`${abs.slice(0, idx)}x`);
}

// Returns the cwd for the NEXT command (changed only by cd/pushd/popd).
function analyzeCommand(sc: SimpleCommand, cwd: string | undefined, out: ShellAnalysis, inPipeline: boolean): string | undefined {
  const shape = shapeOf(sc.words);
  const cmd = shape?.cmd ?? "";
  if (sc.words.length > 0) out.commands.push(sc.words.map((w) => w.text));
  const push = (w: ShellWord, kind: PathRefKind, force = false, command = cmd, redirect = false): void => {
    // Go package patterns: `./...` names a tree of packages, not a file.
    if (/(?:^|\/)\.\.\.$/.test(w.text)) {
      w = { ...w, text: w.text.replace(/\/?\.\.\.$/, "") || "." };
      kind = "list";
    }
    const paths = resolveWord(w, cwd, out);
    if (!paths) return;
    for (const p of paths) {
      if (p.startsWith(`${DYN}search:`)) {
        out.refs.push({ path: p.slice(`${DYN}search:`.length), kind: "search", raw: w.text, command, explicit: true });
        continue;
      }
      const explicit = force || explicitPath(w.text) || w.glob || exists(p);
      out.refs.push({ path: p, kind, raw: w.text, command, explicit, ...(redirect ? { redirect: true } : {}) });
    }
  };

  for (const r of sc.redirects) {
    if (r.op === "<<" || r.op === "<<-" || r.op === "<<<") continue;
    const target = r.target.text;
    if (target.includes(DYN)) {
      out.dynamic.push("redirection to a computed path");
      continue;
    }
    if (/^\/dev\/(?:null|stdout|stderr|stdin|tty|zero|u?random|fd\/\d+)$/.test(target)) continue;
    push(r.target, r.op.includes("<") ? "read" : "write", true, cmd, true);
  }
  if (!shape) return cwd;

  // cd / pushd move the working directory for what follows.
  if (cmd === "cd" || cmd === "pushd") {
    if (inPipeline) return cwd;
    const target = shape.args[0];
    if (target === undefined) return homedir();
    if (target === "-" || target.includes(DYN)) {
      out.dynamic.push(`${cmd} to a computed directory`);
      return undefined;
    }
    const w = shape.argWords[0]!;
    const paths = resolveWord(w, cwd, out);
    const next = paths?.length === 1 && !paths[0]!.startsWith(DYN) ? paths[0] : undefined;
    // Where the shell goes is itself checked (names only), so a `cd` cannot
    // move the working directory somewhere the policy does not cover.
    if (next) out.refs.push({ path: next, kind: "list", raw: target, command: cmd, explicit: true });
    return next;
  }
  if (cmd === "popd") {
    out.dynamic.push("popd");
    return undefined;
  }

  // Opaque execution.
  if (EVAL_COMMANDS.has(cmd)) out.dynamic.push(cmd);
  if (INTERPRETERS.test(cmd)) {
    const inline = shape.flags.find((f) => INLINE_FLAGS.has(f) || /^-[a-z]*c$/.test(f));
    if (inline && SHELLS.test(cmd) && /c$/.test(inline) && shape.args[0] !== undefined && !shape.args[0].includes(DYN)) {
      // `bash -c '…'` / `sh -lc '…'`: a shell script we can read — analyse it.
      analyzeInto(shape.args[0], cwd ?? "/", out, 1);
      return cwd;
    }
    if (inline || shape.args[0] === "eval") {
      out.dynamic.push(`${cmd} ${inline ?? "eval"}`);
      // The program is opaque, the files after it are not: `perl -pi -e '…'
      // FILE` edits FILE in place, `perl -ne '…' FILE` reads it.
      const edits = shape.flags.some((f) => /^-[a-zA-Z]*i/.test(f));
      for (const w of shape.argWords.slice(1)) push(w, edits ? "write" : "read");
      return cwd;
    }
    if (shape.args.length === 0 || shape.args[0] === "-") out.dynamic.push(`${cmd} reading a program from stdin`);
    else {
      // The first positional is the program; it runs, it is not printed.
      const script = shape.argWords.find((w) => !w.flagValue);
      for (const w of shape.argWords) push(w, w === script ? "exec" : "read");
      return cwd;
    }
  }
  if (cmd === "find" && shape.flags.some((f) => f === "-exec" || f === "-execdir" || f === "-ok" || f === "-okdir")) out.dynamic.push("find -exec");

  if (NON_PATH_ARGS.has(cmd)) return cwd;

  const words = sc.words;
  const { pos, dashAt } = positionals(words, cmd);
  const flags = shape.flags;

  // git: content-bearing subcommands read the whole repo without a pathspec.
  if (cmd === "git") {
    analyzeGit(pos, dashAt, flags, cwd, out, push);
    return cwd;
  }

  // Searchers: the first positional of grep/rg/ag/ack is the pattern.
  const patternFirst =
    (cmd === "grep" || cmd === "egrep" || cmd === "fgrep" || cmd === "rg" || cmd === "ag" || cmd === "ack") &&
    !flags.some((f) => f === "-e" || f === "-f" || f.startsWith("--regexp") || f === "--files");
  const targets = patternFirst ? pos.slice(1) : pos;
  const recursive =
    cmd === "rg" ||
    cmd === "ag" ||
    cmd === "ack" ||
    cmd === "fd" ||
    cmd === "fdfind" ||
    cmd === "find" ||
    cmd === "tree" ||
    cmd === "du" ||
    ((cmd === "grep" || cmd === "egrep" || cmd === "fgrep") && hasFlag(flags, ["r", "R"], ["--recursive", "--dereference-recursive"])) ||
    (cmd === "ls" && hasFlag(flags, ["R"], ["--recursive"])) ||
    ((cmd === "zip" || cmd === "rsync" || cmd === "scp" || cmd === "cp") && hasFlag(flags, ["r", "R", "a"], ["--recursive", "--archive"])) ||
    (cmd === "tar" && (hasFlag(flags, ["c"], ["--create"]) || /^c/.test(shape.args[0] ?? "")));

  if (recursive) {
    const explicitTargets = cmd === "find" ? findRoots(words) : targets;
    if (explicitTargets.length === 0 && cwd !== undefined) out.refs.push({ path: cwd, kind: "search", raw: ".", command: cmd, explicit: true });
    else if (explicitTargets.length === 0) out.unknownCwd = true;
    for (const w of explicitTargets) push(w, "search", cmd !== "tar" && cmd !== "zip");
    return cwd;
  }

  if (LIST_ARGS.has(cmd)) {
    if (cmd === "ls" && targets.length === 0) {
      if (cwd !== undefined) out.refs.push({ path: cwd, kind: "list", raw: ".", command: cmd, explicit: true });
      else out.unknownCwd = true;
    }
    for (const w of targets) push(w, "list");
    return cwd;
  }
  if (WRITE_ARGS.has(cmd)) {
    for (const w of targets) push(w, "write");
    return cwd;
  }
  if (cmd === "cp" || cmd === "mv" || cmd === "ln" || cmd === "install") {
    // Sources are read (a copied .env can be printed next); the last is the destination.
    for (const [idx, w] of targets.entries()) push(w, idx === targets.length - 1 && targets.length > 1 ? "write" : "read");
    return cwd;
  }
  // `sed -i` / `--in-place` rewrites its files; otherwise it prints them.
  const sedInPlace = cmd === "sed" && flags.some((f) => /^-[a-zA-Z]*i/.test(f) || f.startsWith("--in-place"));
  if (cmd === "sed") {
    const files = flags.some((f) => f === "-e" || f === "-f" || f.startsWith("--expression") || f.startsWith("--file")) ? targets : targets.slice(1);
    for (const w of files) push(w, sedInPlace ? "write" : "read");
    return cwd;
  }
  // dd names its files as operands: `if=` is read, `of=` is written.
  if (cmd === "dd") {
    for (const w of sc.words) {
      const m = /^(if|of)=(.+)$/.exec(w.text);
      if (m) push({ ...w, text: m[2]! }, m[1] === "if" ? "read" : "write", true);
    }
    return cwd;
  }
  if (cmd === "awk" || cmd === "gawk") {
    // gawk `-i inplace` rewrites its files.
    const words = sc.words.map((w) => w.text);
    const inPlace = words.some((t, k) => (t === "-i" || t === "--include") && words[k + 1] === "inplace");
    const files = flags.some((f) => f === "-f") ? targets : targets.slice(1);
    for (const w of files) if (w.text !== "inplace") push(w, inPlace ? "write" : "read");
    return cwd;
  }
  // Uploaders take files as `@file` / `name=@file` (`curl -d @.env`).
  if (/^(?:curl|wget|http|https|xh)$/.test(cmd)) {
    for (const w of sc.words) {
      const m = /(?:^|=)@(.+)$/.exec(w.text);
      if (m && !m[1]!.includes(DYN)) push({ ...w, text: m[1]! }, "read", true);
    }
  }
  for (const w of targets) push(w, "read");
  return cwd;
}

// `find -L a b -name x` → roots are the words before the first expression.
function findRoots(words: ShellWord[]): ShellWord[] {
  const roots: ShellWord[] = [];
  let j = commandIndex(words) + 1;
  while (j < words.length && /^-[HLP]$/.test(words[j]!.text)) j++;
  for (; j < words.length; j++) {
    const t = words[j]!.text;
    if (t.startsWith("-") || t === "(" || t === "!") break;
    roots.push(words[j]!);
  }
  return roots;
}

const GIT_CONTENT = new Set(["diff", "show", "log", "grep", "blame", "annotate", "cat-file", "archive", "format-patch", "whatchanged", "stash"]);
const GIT_NAMES_ONLY = ["--stat", "--name-only", "--name-status", "--numstat", "--shortstat", "--quiet", "--no-patch", "-s", "--summary", "--dirstat"];
// Any of these brings the patch back, whatever else is on the line.
const GIT_PATCH = /^(?:-p|-u|--patch|--patch-with-stat|--patch-with-raw|-U\d*|--unified(?:=.*)?|--full-diff|-L.*)$/;

function analyzeGit(
  pos: ShellWord[],
  dashAt: number,
  flags: string[],
  cwd: string | undefined,
  out: ShellAnalysis,
  pushAs: (w: ShellWord, kind: PathRefKind, force?: boolean, command?: string) => void,
): void {
  const sub = pos[0]?.text ?? "";
  const rest = pos.slice(1);
  // Refs carry `git <sub>` so policies can tell `git diff` from `git checkout`.
  const push = (w: ShellWord, kind: PathRefKind, force = false): void => pushAs(w, kind, force, `git ${sub}`);
  // `git show HEAD:path` / `git cat-file -p rev:path` name a path inside a rev.
  for (const w of rest) {
    const m = /^[^:\s]*:(.+)$/.exec(w.text);
    if (m && !w.text.includes("://") && (sub === "show" || sub === "cat-file")) push({ ...w, text: m[1]! }, "read", true);
  }
  if (!GIT_CONTENT.has(sub)) {
    // add/commit/status/checkout…: names only. Still resolve explicit paths.
    for (const w of rest) push(w, "list");
    return;
  }
  const patch = flags.some((f) => GIT_PATCH.test(f));
  const namesOnly = !patch && flags.some((f) => GIT_NAMES_ONLY.includes(f.split("=")[0]!));
  const logWithoutPatch = (sub === "log" || sub === "whatchanged") && !patch;
  const stashWithoutPatch = sub === "stash" && !(rest[0]?.text === "show" && flags.some((f) => f === "-p" || f === "--patch"));
  if ((namesOnly && sub !== "grep") || logWithoutPatch || stashWithoutPatch) {
    for (const w of rest) push(w, "list");
    return;
  }
  // `sub` reads content. Pathspecs: after `--`, or bare words naming files.
  const candidates =
    dashAt !== -1 ? pos.slice(Math.max(dashAt, 1)) : (sub === "grep" ? rest.slice(1) : rest).filter((w) => exists(resolve(cwd ?? "/", expandHome(w.text))));
  const pathspecs = candidates.filter((w) => !w.text.includes(DYN));
  if (pathspecs.length === 0) {
    if (cwd === undefined) out.unknownCwd = true;
    else out.refs.push({ path: cwd, kind: "search", raw: ".", command: `git ${sub}`, explicit: true });
    return;
  }
  for (const w of pathspecs) push(w, "search", true);
}

// ---------------------------------------------------------------- secretgate itself

const JS_RUNTIMES = /^(?:node|nodejs|bun|deno)$/;
const PACKAGE_RUNNERS = /^(?:npx|pnpx|bunx)$/;

/**
 * The secretgate subcommand an argv runs (`["secretgate", "disable"]` →
 * "disable"; `vault clear` → "vault clear"), recognising `secretgate`,
 * `node …/secretgate.mjs`, `npx secretgate` and `pnpm exec|dlx secretgate`,
 * after quote removal (`secretgate 'disable'` is still `disable`). A program
 * that cannot be known statically (`$SG disable`) yields "?<first arg>".
 */
export function secretgateInvocation(argv: string[]): string | undefined {
  const words = argv.map((text) => ({ text, glob: false, brace: false }));
  let i = commandIndex(words);
  const first = argv[i];
  if (first === undefined) return undefined;
  const skipFlags = (j: number): number => {
    while (j < argv.length && argv[j]!.startsWith("-")) j++;
    return j;
  };
  const sub = (j: number): string | undefined => {
    const k = skipFlags(j);
    const verb = argv[k];
    if (verb === undefined) return undefined;
    const next = argv[skipFlags(k + 1)];
    return verb === "vault" && next ? `vault ${next}` : verb;
  };
  const name = basename(first);
  if (first.includes(DYN)) {
    const verb = sub(i + 1);
    return verb ? `?${verb}` : undefined;
  }
  if (name === "secretgate" || name === "secretgate.mjs") return sub(i + 1);
  if (JS_RUNTIMES.test(name)) {
    const j = skipFlags(i + 1);
    return argv[j] !== undefined && basename(argv[j]!) === "secretgate.mjs" ? sub(j + 1) : undefined;
  }
  if (PACKAGE_RUNNERS.test(name)) i = skipFlags(i + 1) - 1;
  else if (/^(?:pnpm|yarn|npm)$/.test(name) && /^(?:exec|dlx|x)$/.test(argv[i + 1] ?? "")) i = skipFlags(i + 2) - 1;
  else return undefined;
  return /^secretgate(?:@.*)?$/.test(argv[i + 1] ?? "") ? sub(i + 2) : undefined;
}
