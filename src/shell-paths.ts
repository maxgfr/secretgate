import { readdirSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { expandBraces as expandBraceText } from "./engine/allowlist.js";
import { exists, expandHome, globStaticDir, isDirectory, repositoryRoot } from "./paths.js";

export { expandHome } from "./paths.js";

// Best-effort static analysis of a shell command: which paths does it read,
// write, list or search, and which parts cannot be known without running it.
// Shared by the sensitive-path deny and the scope check so both see the same
// words. It is a tokenizer, not a shell: it understands quoting, escapes,
// separators, redirections, heredocs, `cd`, globs, brace lists and sequences,
// wrappers (`sudo -u x`, `env -C dir`), inline shells (`bash -c '…' a0 a1`)
// and flags everything it cannot resolve statically ($VAR, $(…), eval…) so the
// caller can decide how strict to be. The agent's own sandbox stays the hard
// boundary; this is the layer that keeps honest mistakes out of the model.

/** Marks an unresolved expansion inside a word. Never a valid path byte. */
const DYN = "\u0000";

export interface ShellWord {
  /** Word after quote removal; DYN marks an unresolved expansion. */
  text: string;
  /** Contains an unquoted glob character (`*`, `?`, `[`). */
  glob: boolean;
  /** Contains an unquoted `{…}` group. */
  brace: boolean;
  /** The value of an option (`--flag=value`), not a positional argument. */
  flagValue?: boolean;
  /** Some of it was quoted or escaped (a quoted heredoc delimiter runs nothing). */
  quoted?: boolean;
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
  /** What those feed it, when it is literal text (a script for `bash <<EOF`). */
  stdinText?: string;
}

// read: content may be printed · write: created/changed · list: names or
// metadata only · search: everything below is read · exec: a script an
// interpreter runs (`node x.js`, `python y.py`).
export type PathRefKind = "read" | "write" | "list" | "search" | "exec";

/** How a recursive reader walks a directory, for the bounded sensitive check. */
export interface WalkSpec {
  /** Dot entries are read (grep -r, tar) or skipped (rg, ag by default). */
  hidden: boolean;
  /** .gitignore'd entries are skipped (rg, ag by default). */
  ignore: boolean;
  /** Only files whose name matches one of these (grep --include, rg -g, find -name). */
  include: string[];
  exclude: string[];
  excludeDir: string[];
}

export interface PathRef {
  /** Absolute, `~`-expanded, lexically resolved (not realpath'd). A name-only
   *  ref (explicit: false, from a word that could not be resolved) carries the
   *  known tail of the word instead, relative. */
  path: string;
  kind: PathRefKind;
  /** The word as written (for messages). */
  raw: string;
  /** Command the path belongs to (basename; `git <sub>` for git). */
  command: string;
  /** Written as an explicit path (`/x`, `./x`, `~/x`, a redirection, a glob) or
   *  names something on disk. False for a bare word that may just as well be a
   *  ref or a message (`origin/main`), or a word that could not be resolved:
   *  name-based checks (sensitive files) still look at those, existence-based
   *  ones (scope) skip them. */
  explicit: boolean;
  /** Came from a redirection (`< file`, `> file`), whatever the command. */
  redirect?: boolean;
  /** The value of an option (`--env-file=.env`), not a positional argument. */
  fromOption?: boolean;
  /** A recursive read of this directory prints file content: how it walks. */
  walk?: WalkSpec;
  /** `ln`/`mv`/`cp` source: the second name the command gives it. */
  aliasTo?: string;
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

type Op = "&&" | "||" | ";" | "&" | "|" | "\n";

interface ParseState {
  commands: SimpleCommand[];
  /** Sources of $(…), `…`, <(…), >(…), each with the index of the command it
   *  belongs to — analysed with that command's working directory. */
  substitutions: Array<{ text: string; at: number }>;
  dynamic: string[];
  /** Commands, subshell bounds and the operators between them. */
  structure: Array<{ type: "cmd"; index: number } | { type: "open" } | { type: "close" } | { type: "op"; op: Op }>;
}

interface TokenizeOptions {
  /** The working directory, when it is known for certain ($PWD). */
  cwd: string | undefined;
  /** `$0…$n` of an inline script (`bash -c 'cat $1' a0 file`). */
  positional?: string[];
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

// Commands run from inside an arithmetic expression `$(( $(cat x) ))`, or from
// an unquoted heredoc body: its `$(…)` and backticks run.
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

// Decode `$'…'` starting after the opening quote. Like bash, a NUL ends the
// string (`$'.env\x00junk'` is `.env`) — and it must, since a NUL here would
// otherwise read as the DYN marker and hide the word from every check.
function ansiC(s: string, start: number): { text: string; end: number } {
  let text = "";
  let cut = false;
  let i = start;
  const add = (ch: string): void => {
    if (ch === "\u0000") cut = true;
    if (!cut) text += ch;
  };
  while (i < s.length && s[i] !== "'") {
    if (s[i] !== "\\") {
      add(s[i]!);
      i++;
      continue;
    }
    const n = s[i + 1] ?? "";
    const hex = /^x([0-9a-fA-F]{1,2})/.exec(s.slice(i + 1));
    const uni = /^[uU]([0-9a-fA-F]{1,8})/.exec(s.slice(i + 1));
    const oct = /^([0-7]{1,3})/.exec(s.slice(i + 1));
    if (hex) {
      add(String.fromCharCode(Number.parseInt(hex[1]!, 16)));
      i += 1 + hex[0].length;
    } else if (uni) {
      add(String.fromCodePoint(Math.min(Number.parseInt(uni[1]!, 16), 0x10ffff)));
      i += 1 + uni[0].length;
    } else if (oct) {
      add(String.fromCharCode(Number.parseInt(oct[1]!, 8)));
      i += 1 + oct[0].length;
    } else {
      add(ANSI_ESCAPES[n] ?? n);
      i += 2;
    }
  }
  return { text, end: Math.min(i + 1, s.length) };
}

const VAR_RE = /^[A-Za-z_][A-Za-z0-9_]*/;

function tokenize(command: string, opts: TokenizeOptions): ParseState {
  const st: ParseState = { commands: [], substitutions: [], dynamic: [], structure: [] };
  const fresh = (): SimpleCommand => ({ words: [], redirects: [], stdinLiteral: false });
  let cur = fresh();
  let word = "";
  let inWord = false;
  let glob = false;
  let brace = false;
  let quoted = false;
  let pendingRedirect: string | undefined;
  const heredocs: Array<{ delim: string; strip: boolean; quoted: boolean; owner: number }> = [];
  let i = 0;

  // A substitution belongs to the command being built; it is pushed next, so
  // its index is the current length.
  const substitution = (text: string): void => {
    st.substitutions.push({ text, at: st.commands.length });
  };
  const endWord = (): void => {
    if (!inWord) return;
    const w: ShellWord = { text: word, glob, brace, ...(quoted ? { quoted: true } : {}) };
    if (pendingRedirect) {
      cur.redirects.push({ op: pendingRedirect, target: w });
      if (pendingRedirect === "<<" || pendingRedirect === "<<-") {
        heredocs.push({ delim: word.replaceAll(DYN, ""), strip: pendingRedirect === "<<-", quoted, owner: st.commands.length });
        cur.stdinLiteral = true;
      }
      if (pendingRedirect === "<<<") {
        cur.stdinLiteral = true;
        cur.stdinText = `${cur.stdinText ?? ""}${word}\n`;
      }
      pendingRedirect = undefined;
    } else cur.words.push(w);
    word = "";
    inWord = false;
    glob = false;
    brace = false;
    quoted = false;
  };
  const endCommand = (): void => {
    endWord();
    if (cur.words.length > 0 || cur.redirects.length > 0) {
      st.structure.push({ type: "cmd", index: st.commands.length });
      st.commands.push(cur);
    }
    cur = fresh();
  };
  const positional = (name: string): string | undefined => (opts.positional && /^\d+$/.test(name) ? (opts.positional[Number(name)] ?? "") : undefined);
  const expandVar = (name: string): string => {
    if (name === "HOME") return homedir();
    if (name === "PWD" && opts.cwd !== undefined) return opts.cwd;
    const p = positional(name);
    if (p !== undefined) return p;
    st.dynamic.push(`$${name}`);
    return DYN;
  };
  // `$@` / `$*` of an inline script: one word per argument (`"$*"` joins them).
  const allArgs = (joined: boolean): void => {
    const args = opts.positional!.slice(1);
    if (joined || args.length === 0) {
      word += args.join(" ");
      return;
    }
    word += args[0]!;
    for (const a of args.slice(1)) {
      inWord = true;
      const wasQuoted = quoted;
      endWord();
      word = a;
      inWord = true;
      quoted = wasQuoted;
    }
  };

  while (i < command.length) {
    const c = command[i]!;
    // Heredoc bodies start on the line after their `<<DELIM` and are data.
    // The delimiter word may end right at this newline: close it first.
    if (c === "\n") {
      endWord();
      if (heredocs.length > 0) {
        endCommand();
        st.structure.push({ type: "op", op: "\n" });
        i++;
        for (const h of heredocs.splice(0)) {
          const body: string[] = [];
          while (i < command.length) {
            const nl = command.indexOf("\n", i);
            const line = command.slice(i, nl === -1 ? command.length : nl);
            i = nl === -1 ? command.length : nl + 1;
            if ((h.strip ? line.replace(/^\t+/, "") : line) === h.delim) break;
            body.push(line);
            // An unquoted body still runs $(…) and backticks; a quoted one is inert.
            if (!h.quoted) for (const text of innerSubstitutions(line)) st.substitutions.push({ text, at: h.owner });
          }
          const owner = st.commands[h.owner];
          if (owner) owner.stdinText = `${owner.stdinText ?? ""}${body.join("\n")}\n`;
        }
        continue;
      }
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
        quoted = true;
        i += 2;
      }
    } else if (c === "'") {
      const end = command.indexOf("'", i + 1);
      word += command.slice(i + 1, end === -1 ? command.length : end);
      inWord = true;
      quoted = true;
      i = end === -1 ? command.length : end + 1;
    } else if (c === '"') {
      inWord = true;
      quoted = true;
      i++;
      while (i < command.length && command[i] !== '"') {
        const d = command[i]!;
        if (d === "\\" && i + 1 < command.length && '"\\$`\n'.includes(command[i + 1]!)) {
          if (command[i + 1] !== "\n") word += command[i + 1];
          i += 2;
        } else if (d === "$" && command[i + 1] === "(") {
          const end = matchParen(command, i + 2);
          substitution(command.slice(i + 2, end - 1));
          st.dynamic.push("$(…)");
          word += DYN;
          i = end;
        } else if (d === "`") {
          const end = matchBacktick(command, i + 1);
          substitution(command.slice(i + 1, end - 1));
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
        } else if (d === "$" && opts.positional && /^[0-9@*]/.test(command[i + 1] ?? "")) {
          const p = command[i + 1]!;
          if (p === "@" || p === "*") allArgs(p === "*");
          else word += positional(p)!;
          i += 2;
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
      quoted = true;
      i = end;
    } else if (c === "$" && command[i + 1] === '"') {
      // Locale quoting `$"…"` behaves like "…".
      i++;
    } else if (c === "$" && command[i + 1] === "(") {
      const arithmetic = command[i + 2] === "(";
      const end = matchParen(command, i + 2);
      if (!arithmetic) substitution(command.slice(i + 2, end - 1));
      else for (const text of innerSubstitutions(command.slice(i + 3, end - 2))) substitution(text);
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
    } else if (c === "$" && opts.positional && /^[0-9@*]/.test(command[i + 1] ?? "")) {
      const p = command[i + 1]!;
      inWord = true;
      if (p === "@" || p === "*") allArgs(false);
      else word += positional(p)!;
      i += 2;
    } else if (c === "$" && /^[0-9@*#?$!-]/.test(command[i + 1] ?? "")) {
      st.dynamic.push(`$${command[i + 1]}`);
      word += DYN;
      inWord = true;
      i += 2;
    } else if (c === "`") {
      const end = matchBacktick(command, i + 1);
      substitution(command.slice(i + 1, end - 1));
      st.dynamic.push("`…`");
      word += DYN;
      inWord = true;
      i = end;
    } else if ((c === "<" || c === ">") && command[i + 1] === "(") {
      // Process substitution: the inner command runs; the word is a pipe path.
      endWord();
      const end = matchParen(command, i + 2);
      substitution(command.slice(i + 2, end - 1));
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
      for (const text of innerSubstitutions(command.slice(i + 2, Math.max(i + 2, end - 2)))) substitution(text);
      i = end;
    } else if (SEP_CHARS.has(c)) {
      endCommand();
      const twice = (c === "&" || c === "|" || c === ";") && command[i + 1] === c;
      if (c === "(") st.structure.push({ type: "open" });
      else if (c === ")") st.structure.push({ type: "close" });
      else if (c === "&") st.structure.push({ type: "op", op: twice ? "&&" : "&" });
      else if (c === "|") st.structure.push({ type: "op", op: twice ? "||" : "|" });
      else st.structure.push({ type: "op", op: c === ";" ? ";" : "\n" });
      i += twice ? 2 : 1;
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

const BRACE_LIMIT = 256;

/** `{a,b}c` → [ac, bc]; `{1..3}` → [1, 2, 3]. Unbalanced braces stay literal. */
export function expandBraces(text: string, limit = BRACE_LIMIT): string[] {
  return expandBraceText(text, { limit, sequences: true }).slice(0, limit);
}

// One path segment of a glob as a regex. A bracket expression the engine
// rejects (`[z-a]`) matches nothing, as in bash — it must not throw.
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
  try {
    return new RegExp(`^${re}$`);
  } catch {
    return /(?!)/;
  }
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

type Resolved = { type: "path"; path: string } | { type: "search"; path: string } | { type: "name"; name: string };

// What a word names, from one working directory. A word that cannot be
// resolved (an expansion, `~user`, an unknown cwd) still yields the part of
// it that is known, for the name-based checks: `$DIR/.env` is a `.env`.
function resolveWord(w: ShellWord, cwd: string | undefined, out: ShellAnalysis): Resolved[] {
  let variants = [w.text];
  if (w.brace) {
    variants = expandBraceText(w.text, { limit: BRACE_LIMIT, sequences: true });
    if (variants.length > BRACE_LIMIT) {
      out.dynamic.push(`brace expansion past ${BRACE_LIMIT} words`);
      variants = variants.slice(0, BRACE_LIMIT);
    }
  }
  const result: Resolved[] = [];
  const nameOnly = (tail: string): void => {
    const name = tail.replace(/^\/+/, "");
    if (name !== "") result.push({ type: "name", name });
  };
  for (const v of variants) {
    if (v.includes(DYN)) {
      nameOnly(v.slice(v.lastIndexOf(DYN) + 1));
      continue;
    }
    // `~+` is $PWD; `~-` ($OLDPWD) and `~user` cannot be resolved here.
    if (/^~\+(?:\/|$)/.test(v) && cwd !== undefined) {
      result.push({ type: "path", path: resolve(cwd, `.${v.slice(2)}`) });
      continue;
    }
    if (/^~[^/]/.test(v)) {
      out.dynamic.push(v.split("/")[0]!);
      out.unknownCwd = true;
      const slash = v.indexOf("/");
      if (slash !== -1) nameOnly(v.slice(slash));
      continue;
    }
    const expanded = expandHome(v);
    if (!isAbsolute(expanded) && cwd === undefined) {
      out.unknownCwd = true;
      nameOnly(expanded);
      continue;
    }
    const abs = resolve(cwd ?? "/", expanded);
    if (w.glob && /[*?[]/.test(v)) {
      const g = expandGlob(abs);
      // Too many matches: treat as a search of the glob's static prefix.
      if (g.overflow) result.push({ type: "search", path: globStaticDir(abs) });
      else for (const m of g.matches) result.push({ type: "path", path: m });
    } else result.push({ type: "path", path: abs });
  }
  return result;
}

// ---------------------------------------------------------------- options

interface OptionSpec {
  /** Options that take a value (`-n 5`, `-n5`, `--lines 5`, `--lines=5`). */
  valued?: string[];
  /** …of which the value is a file the command reads. */
  paths?: string[];
  /** Options stop at the first positional (the rest belongs to a program). */
  stopAtPositional?: boolean;
}

interface ParsedArgs {
  /** Positional arguments, in order. */
  pos: ShellWord[];
  /** Index in `pos` where a `--` appeared (-1 when none). */
  dashAt: number;
  /** Option words as written (`-rn`, `--include=*.ts`). */
  flags: string[];
  /** Option values, by option (`--include` → `*.ts`). */
  values: Array<{ flag: string; word: ShellWord }>;
  /** Index of the first word not consumed (with stopAtPositional). */
  next: number;
}

// One option parser for every command: POSIX short clusters (`-rn`, `-n5`,
// `-pe1`), GNU long options (`--x=v`, `--x v`), `--`, and per-command tables of
// which options take a value. A value is never mistaken for a positional
// (`grep --include '*.ts' foo src`), and positionals keep their order.
function parseArgs(words: ShellWord[], start: number, spec: OptionSpec = {}): ParsedArgs {
  const valued = new Set(spec.valued ?? []);
  const res: ParsedArgs = { pos: [], dashAt: -1, flags: [], values: [], next: words.length };
  let j = start;
  for (; j < words.length; j++) {
    const w = words[j]!;
    const t = w.text;
    if (res.dashAt === -1 && t === "--") {
      res.dashAt = res.pos.length;
      if (spec.stopAtPositional) {
        res.next = j + 1;
        return res;
      }
      continue;
    }
    if (res.dashAt !== -1 || !t.startsWith("-") || t === "-") {
      if (spec.stopAtPositional) {
        res.next = j;
        return res;
      }
      res.pos.push(w);
      continue;
    }
    res.flags.push(t);
    // Single-dash long options (`openssl -out FILE`, `find -name X`) are named whole.
    if (valued.has(t) && !/^-[A-Za-z]$/.test(t)) {
      if (j + 1 < words.length) res.values.push({ flag: t, word: { ...words[++j]!, flagValue: true } });
      continue;
    }
    if (t.startsWith("--")) {
      const eq = t.indexOf("=");
      const name = eq === -1 ? t : t.slice(0, eq);
      if (eq !== -1) res.values.push({ flag: name, word: { ...w, text: t.slice(eq + 1), flagValue: true } });
      else if (valued.has(name) && j + 1 < words.length) res.values.push({ flag: name, word: { ...words[++j]!, flagValue: true } });
      continue;
    }
    for (let k = 1; k < t.length; k++) {
      const flag = `-${t[k]}`;
      if (!valued.has(flag)) continue;
      const rest = t.slice(k + 1);
      if (rest !== "") res.values.push({ flag, word: { ...w, text: rest, flagValue: true } });
      else if (j + 1 < words.length) res.values.push({ flag, word: { ...words[++j]!, flagValue: true } });
      break;
    }
  }
  res.next = j;
  return res;
}

const optionValues = (p: ParsedArgs, ...flags: string[]): ShellWord[] => p.values.filter((v) => flags.includes(v.flag)).map((v) => v.word);

const hasFlag = (flags: string[], short: string[], long: string[]): boolean =>
  flags.some((f) => long.includes(f.split("=")[0]!) || (/^-[A-Za-z]+$/.test(f) && short.some((s) => f.includes(s))));

// Value-taking options, per command. A value listed in `paths` is read; any
// other is a pattern, a number or a name, never a path.
const COMMAND_SPECS: Record<string, OptionSpec> = {
  grep: {
    valued: [
      "-e",
      "--regexp",
      "-f",
      "--file",
      "-m",
      "--max-count",
      "-A",
      "-B",
      "-C",
      "--after-context",
      "--before-context",
      "--context",
      "--include",
      "--exclude",
      "--exclude-dir",
      "--exclude-from",
      "--color",
      "--colour",
      "--label",
      "--binary-files",
      "-d",
      "--directories",
      "-D",
      "--devices",
      "--group-separator",
    ],
    paths: ["-f", "--file", "--exclude-from"],
  },
  rg: {
    valued: [
      "-e",
      "--regexp",
      "-f",
      "--file",
      "-g",
      "--glob",
      "--iglob",
      "-t",
      "--type",
      "-T",
      "--type-not",
      "--type-add",
      "--type-clear",
      "-m",
      "--max-count",
      "-A",
      "-B",
      "-C",
      "--after-context",
      "--before-context",
      "--context",
      "-M",
      "--max-columns",
      "--max-depth",
      "-d",
      "--max-filesize",
      "-j",
      "--threads",
      "-E",
      "--encoding",
      "--sort",
      "--sortr",
      "-r",
      "--replace",
      "--pre",
      "--pre-glob",
      "--color",
      "--colors",
      "--context-separator",
      "--path-separator",
      "--engine",
      "--ignore-file",
    ],
    paths: ["-f", "--file", "--ignore-file"],
  },
  ag: {
    valued: [
      "-G",
      "--file-search-regex",
      "-g",
      "--ignore",
      "--ignore-dir",
      "-A",
      "-B",
      "-C",
      "-m",
      "--max-count",
      "--depth",
      "-p",
      "--path-to-ignore",
      "-W",
      "--width",
    ],
    paths: ["-p", "--path-to-ignore"],
  },
  ack: { valued: ["--type", "--match", "--ignore-dir", "--ignore-file", "-A", "-B", "-C", "-m", "--max-count"] },
  head: { valued: ["-n", "-c", "--lines", "--bytes"] },
  tail: { valued: ["-n", "-c", "--lines", "--bytes", "-s", "--sleep-interval", "--pid"] },
  sed: { valued: ["-e", "--expression", "-f", "--file", "-l", "--line-length"], paths: ["-f", "--file"] },
  awk: {
    valued: ["-f", "--file", "-v", "--assign", "-F", "--field-separator", "-i", "--include", "-l", "--load", "-E", "--exec"],
    paths: ["-f", "--file", "-E", "--exec"],
  },
  xargs: {
    valued: [
      "-a",
      "--arg-file",
      "-n",
      "--max-args",
      "-L",
      "--max-lines",
      "-s",
      "--max-chars",
      "-P",
      "--max-procs",
      "-d",
      "--delimiter",
      "-E",
      "--eof",
      "-I",
      "--replace",
      "--process-slot-var",
    ],
    paths: ["-a", "--arg-file"],
    stopAtPositional: true,
  },
  tar: {
    valued: [
      "-f",
      "--file",
      "-C",
      "--directory",
      "-T",
      "--files-from",
      "-X",
      "--exclude-from",
      "--exclude",
      "-b",
      "--blocking-factor",
      "-H",
      "--format",
      "--transform",
      "-I",
      "--use-compress-program",
      "--owner",
      "--group",
      "--mode",
      "--mtime",
    ],
    paths: ["-T", "--files-from"],
  },
  zip: { valued: ["-P", "--password", "-b", "-n", "-t", "-tt", "-O", "-Z"] },
  openssl: { valued: ["-out", "-keyout", "-passout", "-passin", "-subj", "-days"] },
  curl: {
    valued: [
      "-H",
      "--header",
      "-X",
      "--request",
      "-A",
      "--user-agent",
      "-e",
      "--referer",
      "-w",
      "--write-out",
      "-m",
      "--max-time",
      "--connect-timeout",
      "-x",
      "--proxy",
      "-u",
      "--user",
    ],
  },
  find: {},
};
COMMAND_SPECS.egrep = COMMAND_SPECS.grep!;
COMMAND_SPECS.fgrep = COMMAND_SPECS.grep!;
COMMAND_SPECS.gawk = COMMAND_SPECS.awk!;

// ---------------------------------------------------------------- wrappers

interface WrapperSpec extends OptionSpec {
  /** Positional arguments before the wrapped command (`timeout 5 cmd`). */
  positional?: number;
}

// Commands that run another command: their options (some valued) are skipped
// to find it. `sudo -u root cat .env` runs `cat`, not `root`.
const WRAPPERS: Record<string, WrapperSpec> = {
  sudo: {
    valued: [
      "-u",
      "--user",
      "-g",
      "--group",
      "-h",
      "--host",
      "-p",
      "--prompt",
      "-C",
      "--close-from",
      "-D",
      "--chdir",
      "-r",
      "--role",
      "-t",
      "--type",
      "-U",
      "--other-user",
      "-T",
      "--command-timeout",
    ],
  },
  doas: { valued: ["-u", "-C"] },
  env: { valued: ["-u", "--unset", "-C", "--chdir", "-S", "--split-string", "-P"] },
  nice: { valued: ["-n", "--adjustment"] },
  timeout: { valued: ["-k", "--kill-after", "-s", "--signal"], positional: 1 },
  flock: { valued: ["-w", "--wait", "--timeout", "-E", "--conflict-exit-code", "-c", "--command"], positional: 1 },
  watch: { valued: ["-n", "--interval", "-q", "--equexit"] },
  chrt: { positional: 1 },
  ionice: { valued: ["-c", "--class", "-n", "--classdata", "-p", "--pid", "-P", "--pgid", "-u", "--uid"] },
  stdbuf: { valued: ["-i", "--input", "-o", "--output", "-e", "--error"] },
  time: { valued: ["-f", "--format", "-o", "--output"] },
  nohup: {},
  command: {},
  builtin: {},
  exec: { valued: ["-a"] },
  caffeinate: { valued: ["-t", "-w"] },
};

const KEYWORDS = new Set(["if", "then", "else", "elif", "fi", "do", "done", "while", "until", "!", "{", "}"]);
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;

interface Unwrapped {
  /** Index of the word that names the command (words.length when none). */
  index: number;
  /** `env -C dir`: the directory the command runs in. */
  cwdWord?: ShellWord;
  /** `env -S '…'`, `watch '…'`, `flock f -c '…'`: a script to analyse instead. */
  script?: string;
}

// The real command behind leading assignments (`FOO=bar`), shell keywords
// (`then`, `do`, `!`) and wrappers.
function unwrap(words: ShellWord[]): Unwrapped {
  let k = 0;
  let cwdWord: ShellWord | undefined;
  for (;;) {
    while (k < words.length && (ASSIGNMENT.test(words[k]!.text) || KEYWORDS.has(words[k]!.text))) k++;
    if (k >= words.length) return { index: k, cwdWord };
    const name = basename(words[k]!.text);
    const spec = WRAPPERS[name];
    if (!spec) return { index: k, cwdWord };
    const p = parseArgs(words, k + 1, { ...spec, stopAtPositional: true });
    k = p.next;
    if (name === "env") {
      while (k < words.length && ASSIGNMENT.test(words[k]!.text)) k++;
      cwdWord = optionValues(p, "-C", "--chdir")[0] ?? cwdWord;
      const split = optionValues(p, "-S", "--split-string")[0];
      if (split) return { index: words.length, cwdWord, script: [split.text, ...words.slice(k).map((w) => quoteArg(w.text))].join(" ") };
    }
    if (name === "watch" && !p.flags.some((f) => f === "-x" || f === "--exec")) {
      // watch hands its arguments, joined, to `sh -c`.
      return {
        index: words.length,
        cwdWord,
        script: words
          .slice(k)
          .map((w) => w.text)
          .join(" "),
      };
    }
    if (name === "chrt" && p.flags.some((f) => /^-[a-z]*p/.test(f) || f === "--pid")) return { index: words.length, cwdWord };
    k += spec.positional ?? 0;
    if (name === "flock") {
      const inline = optionValues(p, "-c", "--command")[0] ?? (/^(?:-c|--command)$/.test(words[k]?.text ?? "") ? words[k + 1] : undefined);
      if (inline) return { index: words.length, cwdWord, script: inline.text };
    }
  }
}

// ---------------------------------------------------------------- semantics

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
const SHELLS = /^(?:bash|sh|zsh|dash|ksh)$/;
const EVAL_COMMANDS = new Set(["eval", "source", ".", "xargs", "parallel"]);

// How each interpreter takes an inline program, and which of its options
// take a value. perl and ruby read `-e` from the rest of a cluster (`-pe1`).
const INTERPRETER_SPECS: Array<{ re: RegExp; inline: string[]; valued: string[] }> = [
  { re: /^perl$/, inline: ["-e", "-E"], valued: [] },
  { re: /^ruby$/, inline: ["-e"], valued: ["-r", "-I", "-C", "-E", "-W", "-x", "-F"] },
  { re: /^python[0-9.]*$/, inline: ["-c"], valued: ["-m", "-W", "-X"] },
  {
    re: /^(?:node|nodejs|bun)$/,
    inline: ["-e", "--eval", "-p", "--print"],
    valued: ["-r", "--require", "--import", "--loader", "-C", "--conditions", "--input-type", "--title"],
  },
  { re: /^deno$/, inline: ["eval"], valued: [] },
  { re: /^php$/, inline: ["-r"], valued: ["-d", "-c", "-B", "-R", "-E"] },
  { re: /^(?:lua|osascript)$/, inline: ["-e"], valued: ["-l"] },
  { re: /^(?:pwsh|powershell)$/, inline: ["-Command", "-c"], valued: ["-File", "-f"] },
];

/** git subcommands that print file content (see analyzeGit for the flags). */
export const GIT_CONTENT = new Set([
  "diff",
  "show",
  "log",
  "grep",
  "blame",
  "annotate",
  "cat-file",
  "archive",
  "format-patch",
  "whatchanged",
  "stash",
  "fast-export",
  "reflog",
  "range-diff",
  "notes",
]);

/** Is `command` (as a PathRef names it: `git show`) a git content command? */
export function isGitContentCommand(command: string): boolean {
  return command.startsWith("git ") && GIT_CONTENT.has(command.slice(4));
}

export interface AnalyzeOptions {
  cwd: string;
}

interface Context {
  out: ShellAnalysis;
  /** `ln -s a b && cat b`: second names given to files, b → [a]. */
  aliases: Map<string, string[]>;
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
  analyzeInto(command, [opts.cwd], { out, aliases: new Map() }, 0);
  out.dynamic = [...new Set(out.dynamic)];
  const seen = new Set<string>();
  out.refs = out.refs.filter((r) => {
    const key = JSON.stringify([r.kind, r.path, r.command, r.raw, r.explicit, r.redirect, r.fromOption, r.aliasTo, r.walk !== undefined]);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  return out;
}

function quoteArg(a: unknown): string {
  return `'${String(a).replaceAll("'", `'\\''`)}'`;
}

/** Working directories a command may run in: several when a `cd` may have
 *  failed, `undefined` for one that cannot be resolved statically. */
type Cwds = Array<string | undefined>;

const uniqueCwds = (c: Cwds): Cwds => [...new Set(c)];

function analyzeInto(command: string, cwds: Cwds, ctx: Context, depth: number, positional?: string[]): void {
  if (depth > 8) {
    ctx.out.dynamic.push("nested substitution");
    return;
  }
  const st = tokenize(command, { cwd: cwds.length === 1 ? cwds[0] : undefined, positional });
  ctx.out.dynamic.push(...st.dynamic);

  let cur = cwds;
  const stack: Cwds[] = [];
  let prevOp: Op | undefined;
  const nodes = st.structure;
  for (let n = 0; n < nodes.length; n++) {
    const node = nodes[n]!;
    if (node.type === "open") {
      stack.push(cur);
      prevOp = undefined;
      continue;
    }
    if (node.type === "close") {
      cur = stack.pop() ?? cur;
      continue;
    }
    if (node.type === "op") {
      prevOp = node.op;
      continue;
    }
    // Its substitutions run first, in the same directory.
    for (const s of st.substitutions) if (s.at === node.index) analyzeInto(s.text, cur, ctx, depth + 1);
    const after = nodes[n + 1];
    const nextOp = after?.type === "op" ? after.op : undefined;
    const moved = analyzeCommand(st.commands[node.index]!, cur, ctx, depth);
    // A cd in a pipeline or in the background runs in a subshell.
    if (moved && prevOp !== "|" && nextOp !== "|" && nextOp !== "&") {
      // Through `&&` what follows only runs if the cd succeeded. After `;` it
      // runs anyway: only a directory that exists is certain to have been
      // entered. After `||` it runs when the cd failed. Uncertain → both.
      const certain = nextOp === "&&" || ((nextOp === ";" || nextOp === "\n" || nextOp === undefined) && moved.exists);
      cur = certain ? moved.cwds : uniqueCwds([...cur, ...moved.cwds]);
    }
    prevOp = undefined;
  }
  for (const s of st.substitutions) if (st.commands[s.at] === undefined) analyzeInto(s.text, cur, ctx, depth + 1);
}

interface Push {
  force?: boolean;
  command?: string;
  redirect?: boolean;
  fromOption?: boolean;
  walk?: WalkSpec;
  aliasTo?: (path: string) => string | undefined;
}

function explicitPath(text: string): boolean {
  return text.startsWith("/") || text.startsWith("~") || text.startsWith("./") || text.startsWith("../") || text === "." || text === "..";
}

// The cwds a command runs in after `env -C dir` / `git -C dir` / `tar -C dir`.
function cwdsAfter(word: ShellWord | undefined, cwds: Cwds, out: ShellAnalysis): Cwds {
  if (!word) return cwds;
  return uniqueCwds(
    cwds.flatMap((cwd) => {
      const [only, ...more] = resolveWord(word, cwd, out);
      return only?.type === "path" && more.length === 0 ? [only.path] : [undefined];
    }),
  );
}

// Returns the cwds for the NEXT command when this one changes directory
// (cd/pushd/popd), with whether the target certainly exists.
function analyzeCommand(sc: SimpleCommand, cwds: Cwds, ctx: Context, depth: number): { cwds: Cwds; exists: boolean } | undefined {
  const out = ctx.out;
  const unwrapped = unwrap(sc.words);
  const k = unwrapped.index;
  const cmd = k < sc.words.length ? basename(sc.words[k]!.text) : "";
  if (sc.words.length > 0) out.commands.push(sc.words.map((w) => w.text));

  const pushFrom =
    (from: Cwds) =>
    (w: ShellWord, kind: PathRefKind, opts: Push = {}): void => {
      const command = opts.command ?? cmd;
      // Go package patterns: `./...` names a tree of packages, not a file.
      if (/(?:^|\/)\.\.\.$/.test(w.text)) {
        w = { ...w, text: w.text.replace(/\/?\.\.\.$/, "") || "." };
        kind = "list";
      }
      const extra = {
        ...(opts.redirect ? { redirect: true } : {}),
        ...(opts.fromOption || w.flagValue ? { fromOption: true } : {}),
        ...(opts.walk ? { walk: opts.walk } : {}),
      };
      for (const cwd of from) {
        for (const r of resolveWord(w, cwd, out)) {
          if (r.type === "name") {
            out.refs.push({ path: r.name, kind, raw: w.text, command, explicit: false, ...extra });
            continue;
          }
          if (r.type === "search") {
            out.refs.push({ path: r.path, kind: "search", raw: w.text, command, explicit: true, ...extra });
            continue;
          }
          const explicit = opts.force || explicitPath(w.text) || w.glob || exists(r.path);
          const aliasTo = opts.aliasTo?.(r.path);
          out.refs.push({ path: r.path, kind, raw: w.text, command, explicit, ...extra, ...(aliasTo ? { aliasTo } : {}) });
          // A second name given earlier in the command reaches its source.
          if (kind !== "write")
            for (const [dest, sources] of ctx.aliases)
              if (r.path === dest || r.path.startsWith(`${dest}/`))
                for (const src of sources) out.refs.push({ path: src + r.path.slice(dest.length), kind, raw: w.text, command, explicit: true, ...extra });
        }
      }
    };
  const push = pushFrom(cwds);

  for (const r of sc.redirects) {
    if (r.op === "<<" || r.op === "<<-" || r.op === "<<<") continue;
    const target = r.target.text;
    if (target.includes(DYN)) out.dynamic.push("redirection to a computed path");
    if (/^\/dev\/(?:null|stdout|stderr|stdin|tty|zero|u?random|fd\/\d+)$/.test(target)) continue;
    push(r.target, r.op.includes("<") ? "read" : "write", { force: true, redirect: true });
  }

  // A wrapper that hands a whole script to a shell (`env -S`, `watch`, `flock -c`).
  const here = cwdsAfter(unwrapped.cwdWord, cwds, out);
  if (unwrapped.script !== undefined) {
    analyzeInto(unwrapped.script, here, ctx, depth + 1);
    return undefined;
  }
  if (k >= sc.words.length) return undefined;
  if (here !== cwds) {
    // `env -C dir cmd`: the command runs elsewhere; nothing after it moves.
    analyzeCommand({ ...sc, words: sc.words.slice(k), redirects: [] }, here, ctx, depth);
    return undefined;
  }

  // cd / pushd move the working directory for what follows.
  if (cmd === "cd" || cmd === "pushd") {
    const args = parseArgs(sc.words, k + 1, { valued: [] }).pos;
    const target = args[0];
    if (target === undefined && cmd === "cd") return { cwds: [homedir()], exists: true };
    if (target === undefined || target.text === "-" || target.text.includes(DYN)) {
      out.dynamic.push(`${cmd} to a computed directory`);
      return { cwds: [undefined], exists: false };
    }
    const next: Cwds = cwds.map((cwd) => {
      const [only, ...more] = resolveWord(target, cwd, out);
      return only?.type === "path" && more.length === 0 ? only.path : undefined;
    });
    // Where the shell goes is itself checked (names only), so a `cd` cannot
    // move the working directory somewhere the policy does not cover.
    for (const dir of next) if (dir) out.refs.push({ path: dir, kind: "list", raw: target.text, command: cmd, explicit: true });
    return { cwds: uniqueCwds(next), exists: next.every((d) => d !== undefined && isDirectory(d)) };
  }
  if (cmd === "popd") {
    out.dynamic.push("popd");
    return { cwds: [undefined], exists: false };
  }

  // Opaque execution.
  if (EVAL_COMMANDS.has(cmd)) out.dynamic.push(cmd);
  if (cmd === "eval") {
    // eval joins its arguments and runs them: when they are literal, so is the script.
    const text = sc.words.slice(k + 1).map((w) => w.text);
    if (!text.some((t) => t.includes(DYN))) analyzeInto(text.join(" "), cwds, ctx, depth + 1);
    return undefined;
  }
  if (SHELLS.test(cmd)) return analyzeShellCommand(sc, k, cmd, cwds, ctx, depth, push);
  if (INTERPRETERS.test(cmd)) {
    analyzeInterpreter(sc, k, cmd, push, out);
    return undefined;
  }

  if (NON_PATH_ARGS.has(cmd)) return undefined;

  // git: content-bearing subcommands read the whole repo without a pathspec.
  if (cmd === "git") {
    analyzeGit(sc.words, k, cwds, ctx);
    return undefined;
  }

  const spec = COMMAND_SPECS[cmd] ?? {};
  const parsed = parseArgs(sc.words, k + 1, spec);
  const { pos, flags } = parsed;
  // Values of options that name files (`grep -f FILE`, `xargs -a FILE`), and of
  // unknown `--x=value` options, which may.
  const known = new Set(spec.valued ?? []);
  const paths = new Set(spec.paths ?? []);
  const namesOnly = LIST_ARGS.has(cmd) || WRITE_ARGS.has(cmd);
  for (const { flag, word } of parsed.values) if (paths.has(flag) || (!known.has(flag) && !namesOnly)) push(word, "read", { fromOption: true });

  if (cmd === "xargs") {
    // The command xargs runs gets its arguments from stdin: only its fixed ones are known.
    return undefined;
  }

  if (cmd === "find") {
    analyzeFind(sc.words, k, cwds, ctx, depth, push);
    return undefined;
  }

  // Searchers: the first positional of grep/rg/ag/ack is the pattern.
  const searcher = /^(?:grep|egrep|fgrep|rg|ag|ack)$/.test(cmd);
  const patternGiven = parsed.values.some((v) => /^(?:-e|--regexp|-f|--file)$/.test(v.flag)) || (cmd === "rg" && flags.includes("--files"));
  const targets = searcher && !patternGiven ? pos.slice(1) : pos;
  const recursive =
    cmd === "rg" ||
    cmd === "ag" ||
    cmd === "ack" ||
    cmd === "fd" ||
    cmd === "fdfind" ||
    cmd === "tree" ||
    cmd === "du" ||
    ((cmd === "grep" || cmd === "egrep" || cmd === "fgrep") && hasFlag(flags, ["r", "R"], ["--recursive", "--dereference-recursive"])) ||
    (cmd === "ls" && hasFlag(flags, ["R"], ["--recursive"])) ||
    ((cmd === "zip" || cmd === "rsync" || cmd === "scp" || cmd === "cp") && hasFlag(flags, ["r", "R", "a"], ["--recursive", "--archive"])) ||
    (cmd === "tar" && (hasFlag(flags, ["c"], ["--create"]) || /^c/.test(pos[0]?.text ?? "")));

  if (recursive) {
    const walk = contentWalk(cmd, flags, parsed);
    const from = cmd === "tar" ? cwdsAfter(optionValues(parsed, "-C", "--directory")[0], cwds, out) : cwds;
    const pushHere = from === cwds ? push : pushFrom(from);
    if (targets.length === 0) {
      for (const cwd of from) {
        if (cwd !== undefined) out.refs.push({ path: cwd, kind: "search", raw: ".", command: cmd, explicit: true, ...(walk ? { walk } : {}) });
        else out.unknownCwd = true;
      }
    }
    for (const w of targets) pushHere(w, "search", { force: cmd !== "tar" && cmd !== "zip", walk });
    return undefined;
  }

  if (LIST_ARGS.has(cmd)) {
    if (cmd === "ls" && targets.length === 0) {
      for (const cwd of cwds) {
        if (cwd !== undefined) out.refs.push({ path: cwd, kind: "list", raw: ".", command: cmd, explicit: true });
        else out.unknownCwd = true;
      }
    }
    for (const w of targets) push(w, "list");
    return undefined;
  }
  if (WRITE_ARGS.has(cmd)) {
    for (const w of targets) push(w, "write");
    return undefined;
  }
  if (cmd === "cp" || cmd === "mv" || cmd === "ln" || cmd === "install") {
    analyzeAlias(cmd, targets, flags, cwds, ctx, push);
    return undefined;
  }
  // `sed -i` / `-I` (BSD) / `--in-place` rewrites its files; otherwise it prints them.
  if (cmd === "sed") {
    const inPlace = flags.some((f) => /^-[a-zA-Z]*[iI]/.test(f) || f.startsWith("--in-place"));
    const scriptGiven = parsed.values.some((v) => /^(?:-e|--expression|-f|--file)$/.test(v.flag));
    for (const w of scriptGiven ? targets : targets.slice(1)) push(w, inPlace ? "write" : "read");
    return undefined;
  }
  // dd names its files as operands: `if=` is read, `of=` is written.
  if (cmd === "dd") {
    for (const w of sc.words) {
      const m = /^(if|of)=(.+)$/.exec(w.text);
      if (m) push({ ...w, text: m[2]! }, m[1] === "if" ? "read" : "write", { force: true });
    }
    return undefined;
  }
  if (cmd === "awk" || cmd === "gawk") {
    // gawk's inplace extension rewrites its files, however it is loaded:
    // `-i inplace`, `-iinplace`, `--include=inplace`, `@include "inplace"`…
    const inPlace = sc.words.some((w) => w.text.includes("inplace"));
    const programFile = parsed.values.some((v) => v.flag === "-f" || v.flag === "--file");
    for (const w of programFile ? targets : targets.slice(1)) if (!/^inplace(?:\.awk)?$/.test(w.text)) push(w, inPlace ? "write" : "read");
    return undefined;
  }
  // Uploaders take files as `@file` / `name=@file` (`curl -d @.env`).
  if (/^(?:curl|wget|http|https|xh)$/.test(cmd)) {
    for (const w of sc.words) {
      const m = /(?:^|=)@(.+)$/.exec(w.text);
      if (m && !m[1]!.includes(DYN)) push({ ...w, text: m[1]! }, "read", { force: true });
    }
  }
  for (const w of targets) push(w, "read");
  return undefined;
}

// How a recursive command walks what it prints, or undefined when it prints
// names or counts only (`grep -rl`, `rg --files`, `du`, `tree`).
function contentWalk(cmd: string, flags: string[], parsed: ParsedArgs): WalkSpec | undefined {
  const base: WalkSpec = { hidden: true, ignore: false, include: [], exclude: [], excludeDir: [] };
  const texts = (...f: string[]): string[] => optionValues(parsed, ...f).map((w) => w.text);
  if (cmd === "grep" || cmd === "egrep" || cmd === "fgrep") {
    if (hasFlag(flags, ["l", "L", "c", "q"], ["--files-with-matches", "--files-without-match", "--count", "--quiet", "--silent"])) return undefined;
    return { ...base, include: texts("--include"), exclude: texts("--exclude"), excludeDir: texts("--exclude-dir") };
  }
  if (cmd === "rg") {
    if (hasFlag(flags, ["l", "c", "q"], ["--files", "--files-with-matches", "--files-without-match", "--count", "--count-matches", "--quiet"]))
      return undefined;
    const u = flags.reduce((n, f) => n + (/^-[A-Za-z]*u/.test(f) ? (f.match(/u/g) ?? []).length : 0), 0);
    const globs = texts("-g", "--glob", "--iglob");
    return {
      ...base,
      hidden: u >= 2 || flags.includes("--hidden") || flags.includes("-."),
      ignore: u === 0 && !flags.includes("--no-ignore"),
      include: globs.filter((g) => !g.startsWith("!")),
      exclude: globs.filter((g) => g.startsWith("!")).map((g) => g.slice(1)),
    };
  }
  if (cmd === "ag" || cmd === "ack") {
    if (hasFlag(flags, ["l", "L", "c", "g", "f"], ["--files-with-matches", "--files-without-matches", "--count"])) return undefined;
    const unrestricted = hasFlag(flags, ["u"], ["--unrestricted"]);
    return { ...base, hidden: unrestricted || flags.includes("--hidden"), ignore: !unrestricted && !hasFlag(flags, ["U"], ["--skip-vcs-ignores"]) };
  }
  if (cmd === "tar") return { ...base, exclude: texts("--exclude") };
  if (cmd === "zip") return base;
  return undefined;
}

// `find ROOTS EXPR`: a search of its roots. With `-exec cat {} +` (a content
// command), everything it matches is printed — walked like `grep -r`, limited
// to its `-name` patterns when those are all it filters on.
function analyzeFind(
  words: ShellWord[],
  k: number,
  cwds: Cwds,
  ctx: Context,
  depth: number,
  push: (w: ShellWord, kind: PathRefKind, opts?: Push) => void,
): void {
  const out = ctx.out;
  let j = k + 1;
  while (j < words.length && /^-[HLP]$/.test(words[j]!.text)) j++;
  const roots: ShellWord[] = [];
  for (; j < words.length; j++) {
    const t = words[j]!.text;
    if (t.startsWith("-") || t === "(" || t === "!") break;
    roots.push(words[j]!);
  }
  const names: string[] = [];
  let complex = false;
  let readsContent = false;
  for (; j < words.length; j++) {
    const t = words[j]!.text;
    if (t === "-name" || t === "-iname") names.push(words[++j]?.text ?? "");
    else if (t === "-o" || t === "-or" || t === "!" || t === "-not") complex = true;
    else if (t === "-exec" || t === "-execdir" || t === "-ok" || t === "-okdir") {
      out.dynamic.push("find -exec");
      const start = j + 1;
      while (j + 1 < words.length && words[j + 1]!.text !== ";" && words[j + 1]!.text !== "+") j++;
      const argv = words.slice(start, j + 1).filter((w) => !w.text.includes("{}"));
      j++;
      if (argv.length === 0) continue;
      const exec = basename(argv[0]!.text);
      if (/^(?:cat|head|tail|less|more|bat|grep|egrep|fgrep|rg|strings|xxd|od|hexdump|base64|nl|tac|sed|awk|gawk|cp|tar|zip|curl|jq)$/.test(exec))
        readsContent = true;
      analyzeCommand({ words: argv, redirects: [], stdinLiteral: false }, cwds, ctx, depth + 1);
    }
  }
  const walk: WalkSpec | undefined = readsContent ? { hidden: true, ignore: false, include: complex ? [] : names, exclude: [], excludeDir: [] } : undefined;
  if (roots.length === 0) {
    for (const cwd of cwds) {
      if (cwd !== undefined) out.refs.push({ path: cwd, kind: "search", raw: ".", command: "find", explicit: true, ...(walk ? { walk } : {}) });
      else out.unknownCwd = true;
    }
  }
  for (const w of roots) push(w, "search", { force: true, walk });
}

// cp / mv / ln / install: the sources are read (a copied .env can be printed
// next), the last argument is the destination. The second name is recorded,
// so a later `cat` of it in the same command reaches the source.
function analyzeAlias(
  cmd: string,
  targets: ShellWord[],
  flags: string[],
  cwds: Cwds,
  ctx: Context,
  push: (w: ShellWord, kind: PathRefKind, opts?: Push) => void,
): void {
  if (targets.length < 2) {
    for (const w of targets) push(w, "read");
    return;
  }
  const destWord = targets[targets.length - 1]!;
  const sources = targets.slice(0, -1);
  const symbolic = cmd === "ln" && hasFlag(flags, ["s"], ["--symbolic"]);
  for (const cwd of cwds) {
    const dest = resolveWord(destWord, cwd, ctx.out).find((r) => r.type === "path")?.path;
    const intoDir = dest !== undefined && (sources.length > 1 || isDirectory(dest));
    for (const w of sources) {
      // `ln -s TARGET LINK`: a relative TARGET is resolved from the link's directory.
      const base = symbolic && dest !== undefined && !isAbsolute(expandHome(w.text)) ? (intoDir ? dest : dirname(dest)) : cwd;
      for (const r of resolveWord(w, base, ctx.out)) {
        if (r.type !== "path") {
          const path = r.type === "name" ? r.name : r.path;
          ctx.out.refs.push({ path, kind: r.type === "search" ? "search" : "read", raw: w.text, command: cmd, explicit: r.type === "search" });
          continue;
        }
        const name = dest === undefined ? undefined : intoDir ? join(dest, basename(r.path)) : dest;
        const explicit = explicitPath(w.text) || w.glob || exists(r.path);
        ctx.out.refs.push({ path: r.path, kind: "read", raw: w.text, command: cmd, explicit, ...(name ? { aliasTo: name } : {}) });
        if (explicit && name) ctx.aliases.set(name, [...(ctx.aliases.get(name) ?? []), r.path]);
      }
    }
  }
  push(destWord, "write");
}

// `bash -o x -c SCRIPT a0 a1`, `sh script.sh args`, `bash <<< "…"`.
function analyzeShellCommand(
  sc: SimpleCommand,
  k: number,
  cmd: string,
  cwds: Cwds,
  ctx: Context,
  depth: number,
  push: (w: ShellWord, kind: PathRefKind, opts?: Push) => void,
): undefined {
  const parsed = parseArgs(sc.words, k + 1, { valued: ["-o", "+o", "-O", "+O", "--rcfile", "--init-file"], stopAtPositional: true });
  const inline = parsed.flags.some((f) => /^-[A-Za-z]*c[A-Za-z]*$/.test(f));
  const rest = sc.words.slice(parsed.next);
  if (inline) {
    const script = rest[0];
    if (!script || script.text.includes(DYN)) {
      ctx.out.dynamic.push(`${cmd} -c`);
      return undefined;
    }
    // The words after the script are $0, $1, … inside it.
    analyzeInto(
      script.text,
      cwds,
      ctx,
      depth + 1,
      rest.slice(1).map((w) => w.text),
    );
    return undefined;
  }
  if (rest.length === 0) {
    // The program comes on stdin: literal text (`bash <<< "…"`, a heredoc) is a script.
    if (sc.stdinText !== undefined && !sc.stdinText.includes(DYN)) analyzeInto(sc.stdinText, cwds, ctx, depth + 1);
    else ctx.out.dynamic.push(`${cmd} reading a program from stdin`);
    return undefined;
  }
  // `sh script.sh args`: the script runs, it is not printed.
  push(rest[0]!, "exec");
  for (const w of rest.slice(1)) push(w, "read");
  return undefined;
}

// perl/ruby/python/node…: an inline program is opaque, the files after it are
// not (`perl -pi -e '…' FILE` edits FILE in place, `perl -ne '…' FILE` reads
// it). Without one, the first positional is the program: it runs, it is not
// printed; the others are its arguments, read.
function analyzeInterpreter(sc: SimpleCommand, k: number, cmd: string, push: (w: ShellWord, kind: PathRefKind, opts?: Push) => void, out: ShellAnalysis): void {
  const spec: { inline: string[]; valued: string[] } = INTERPRETER_SPECS.find((s) => s.re.test(cmd)) ?? { inline: [], valued: [] };
  const inlineShort = spec.inline.filter((f) => /^-[A-Za-z]$/.test(f));
  const pos: ShellWord[] = [];
  let inline: string | undefined;
  let edits = false;
  for (let j = k + 1; j < sc.words.length; j++) {
    const w = sc.words[j]!;
    const t = w.text;
    if (pos.length > 0 && inline === undefined) {
      // After the program, every word is the program's.
      pos.push(w);
      continue;
    }
    if (spec.inline.includes(t)) {
      inline = t;
      j++;
      continue;
    }
    if (t.startsWith("--")) {
      const eq = t.indexOf("=");
      const name = eq === -1 ? t : t.slice(0, eq);
      if (eq !== -1) push({ ...w, text: t.slice(eq + 1), flagValue: true }, "read", { fromOption: true });
      else if (spec.valued.includes(name) && j + 1 < sc.words.length) push(sc.words[++j]!, "read", { fromOption: true });
      continue;
    }
    if (t.startsWith("-") && t.length > 1) {
      if (/^-[A-Za-z]*i/.test(t) && /^(?:perl|ruby)$/.test(cmd)) edits = true;
      // A cluster: `-pe1` is -p, then -e with `1` as its program.
      for (let c = 1; c < t.length; c++) {
        const flag = `-${t[c]}`;
        if (inlineShort.includes(flag)) {
          inline = flag;
          if (c + 1 >= t.length) j++;
          break;
        }
        if (spec.valued.includes(flag)) {
          if (c + 1 >= t.length && j + 1 < sc.words.length) push(sc.words[++j]!, "read", { fromOption: true });
          break;
        }
      }
      continue;
    }
    pos.push(w);
  }
  if (inline !== undefined) {
    out.dynamic.push(`${cmd} ${inline}`);
    for (const w of pos) push(w, edits ? "write" : "read");
    return;
  }
  if (pos.length === 0) {
    out.dynamic.push(`${cmd} reading a program from stdin`);
    return;
  }
  push(pos[0]!, "exec");
  for (const w of pos.slice(1)) push(w, "read");
}

const GIT_NAMES_ONLY = ["--stat", "--name-only", "--name-status", "--numstat", "--shortstat", "--quiet", "--no-patch", "-s", "--summary", "--dirstat"];
// Any of these brings the patch back, whatever else is on the line.
const GIT_PATCH = /^(?:-p|-u|--patch|--patch-with-stat|--patch-with-raw|-U\d*|--unified(?:=.*)?|--full-diff|-L.*)$/;
// git's own options, before the subcommand; these take a value.
const GIT_GLOBAL_VALUED = new Set(["-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--config-env", "--exec-path", "--list-cmds"]);

function analyzeGit(words: ShellWord[], k: number, cwds: Cwds, ctx: Context): void {
  const out = ctx.out;
  // Global options: `-C dir` moves the cwd (repeatable), `--work-tree` names
  // the tree; `--git-dir=…`, `-c k=v` are never the subcommand.
  let j = k + 1;
  let here = cwds;
  let workTree: ShellWord | undefined;
  for (; j < words.length; j++) {
    const t = words[j]!.text;
    if (!t.startsWith("-")) break;
    const eq = t.indexOf("=");
    const name = eq === -1 ? t : t.slice(0, eq);
    const value = eq !== -1 ? { ...words[j]!, text: t.slice(eq + 1) } : GIT_GLOBAL_VALUED.has(name) && name !== "--exec-path" ? words[++j] : undefined;
    if (name === "-C") here = cwdsAfter(value, here, out);
    if (name === "--work-tree") workTree = value;
  }
  const sub = words[j]?.text ?? "";
  const command = `git ${sub}`;
  const parsed = parseArgs(words, j + 1, {
    valued: ["-n", "--max-count", "--author", "--committer", "--grep", "--since", "--until", "--format", "--pretty", "-m", "-e", "-S", "-G"],
  });
  const { pos, dashAt, flags } = parsed;
  const push = (w: ShellWord, kind: PathRefKind, from: Cwds, force = false): void => {
    for (const cwd of from)
      for (const r of resolveWord(w, cwd, out)) {
        if (r.type === "name") out.refs.push({ path: r.name, kind, raw: w.text, command, explicit: false });
        else out.refs.push({ path: r.path, kind, raw: w.text, command, explicit: force || explicitPath(w.text) || exists(r.path) });
      }
  };
  // The tree a pathspec-less content command prints: the repository's, not
  // just the cwd's (with `--git-dir` alone, git takes the cwd as the top).
  const gitDirOnly = !workTree && words.slice(k + 1, j).some((w) => w.text.startsWith("--git-dir"));
  const roots: Cwds = workTree
    ? cwdsAfter(workTree, here, out)
    : uniqueCwds(here.map((cwd) => (cwd === undefined || gitDirOnly ? cwd : (repositoryRoot(cwd) ?? cwd))));
  // `git show HEAD:path` / `git cat-file -p rev:path` name a path inside a rev,
  // relative to the repository root (`rev:./path` to the cwd).
  for (const w of pos) {
    const m = /^[^:\s]*:(.+)$/.exec(w.text);
    if (!m || w.text.includes("://") || (sub !== "show" && sub !== "cat-file")) continue;
    const relToCwd = /^\.\.?\//.test(m[1]!);
    push({ ...w, text: m[1]! }, "read", relToCwd ? here : roots, true);
  }
  if (!GIT_CONTENT.has(sub)) {
    // add/commit/status/checkout…: names only. Still resolve explicit paths.
    for (const w of pos) push(w, "list", here);
    return;
  }
  const patch = flags.some((f) => GIT_PATCH.test(f));
  const namesOnly = !patch && flags.some((f) => GIT_NAMES_ONLY.includes(f.split("=")[0]!));
  const logWithoutPatch = (sub === "log" || sub === "whatchanged" || sub === "reflog") && !patch;
  const stashWithoutPatch = sub === "stash" && !(pos[0]?.text === "show" && flags.some((f) => f === "-p" || f === "--patch"));
  if ((namesOnly && sub !== "grep") || logWithoutPatch || stashWithoutPatch) {
    for (const w of pos) push(w, "list", here);
    return;
  }
  // `sub` reads content. Pathspecs: after `--`, or bare words naming files.
  const candidates =
    dashAt !== -1
      ? pos.slice(dashAt)
      : (sub === "grep" ? pos.slice(1) : pos).filter((w) => here.some((cwd) => exists(resolve(cwd ?? "/", expandHome(w.text)))));
  const pathspecs = candidates.filter((w) => !w.text.includes(DYN));
  if (pathspecs.length === 0) {
    for (const root of roots) {
      if (root === undefined) out.unknownCwd = true;
      else out.refs.push({ path: root, kind: "search", raw: ".", command, explicit: true });
    }
    return;
  }
  for (const w of pathspecs) push(w, "search", here, true);
}

// ---------------------------------------------------------------- secretgate itself

const JS_RUNTIMES = /^(?:node|nodejs|bun|deno)$/;
const PACKAGE_MANAGERS = /^(?:npx|pnpx|bunx|pnpm|yarn|npm|bun)$/;
const RUNNER_VALUED = new Set([
  "-p",
  "--package",
  "-c",
  "--call",
  "--filter",
  "-F",
  "-C",
  "--dir",
  "--cwd",
  "--prefix",
  "-w",
  "--workspace",
  "--userconfig",
  "--registry",
  "--cache",
]);

/**
 * The secretgate subcommand an argv runs (`["secretgate", "disable"]` →
 * "disable"; `vault clear` → "vault clear"), recognising `secretgate`,
 * `node …/secretgate.mjs`, and every package-manager launcher (`npx
 * [--package secretgate] secretgate`, `pnpm [exec|dlx] secretgate`, `yarn
 * [dlx] secretgate`, `npm exec secretgate`, `bunx`, `bun x`), behind any
 * wrapper (`sudo -u x …`), after quote removal (`secretgate 'disable'` is
 * still `disable`). A program that cannot be known statically (`$SG disable`)
 * yields "?<first arg>".
 */
export function secretgateInvocation(argv: string[]): string | undefined {
  const words = argv.map((text) => ({ text, glob: false, brace: false }));
  const { index, script } = unwrap(words);
  if (script !== undefined) return analyzeShell(script, { cwd: "/" }).commands.map(secretgateInvocation).find(Boolean);
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
  const first = argv[index];
  if (first === undefined) return undefined;
  const name = basename(first);
  if (first.includes(DYN)) {
    const verb = sub(index + 1);
    return verb ? `?${verb}` : undefined;
  }
  const isSelf = (w: string | undefined): boolean => w !== undefined && (/^secretgate(?:@.*)?$/.test(w) || basename(w) === "secretgate.mjs");
  if (name === "secretgate" || name === "secretgate.mjs") return sub(index + 1);
  if (JS_RUNTIMES.test(name)) {
    const j = skipFlags(index + 1);
    if (argv[j] !== undefined && basename(argv[j]!) === "secretgate.mjs") return sub(j + 1);
  }
  if (!PACKAGE_MANAGERS.test(name)) return undefined;
  let j = index + 1;
  let call: string | undefined;
  const skipOptions = (): void => {
    while (j < argv.length && argv[j]!.startsWith("-") && argv[j] !== "--") {
      const t = argv[j]!;
      const eq = t.indexOf("=");
      const flag = eq === -1 ? t : t.slice(0, eq);
      if (flag === "-c" || flag === "--call") call = eq === -1 ? argv[j + 1] : t.slice(eq + 1);
      if (eq === -1 && RUNNER_VALUED.has(flag)) j++;
      j++;
    }
  };
  skipOptions();
  if (!/^(?:npx|pnpx|bunx)$/.test(name) && /^(?:exec|dlx|x|run|run-script)$/.test(argv[j] ?? "")) {
    j++;
    skipOptions();
  }
  if (argv[j] === "--") j++;
  if (call !== undefined) return analyzeShell(call, { cwd: "/" }).commands.map(secretgateInvocation).find(Boolean);
  return isSelf(argv[j]) ? sub(j + 1) : undefined;
}
