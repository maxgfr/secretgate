// Targeted edits to Codex's ~/.codex/config.toml WITHOUT a TOML parser at
// runtime (the shipped bundle stays dependency-free, and a full parse/reprint
// would reorder/reformat the user's file). Two shapes only:
//   - no [features] table -> append a clearly delimited managed block
//   - [features] exists   -> insert/patch `hooks = true # secretgate` inside it
// Anything ambiguous -> throw with the exact manual snippet.

const BLOCK_START = "# >>> secretgate managed >>>";
const BLOCK_END = "# <<< secretgate managed <<<";
const OUR_LINE = "hooks = true # secretgate";

export interface TomlEdit {
  content: string;
  changed: boolean;
}

const MANUAL_SNIPPET = `[features]\nhooks = true`;

function featuresTableRange(lines: string[]): { start: number; end: number } | undefined {
  const start = lines.findIndex((l) => /^\s*\[features\]\s*(#.*)?$/.test(l));
  if (start === -1) return undefined;
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i++) {
    if (/^\s*\[/.test(lines[i]!)) {
      end = i;
      break;
    }
  }
  return { start, end };
}

export function enableHooksFeature(content: string): TomlEdit {
  const lines = content.split("\n");
  const range = featuresTableRange(lines);
  if (range) {
    const table = lines.slice(range.start + 1, range.end);
    if (table.some((l) => /^\s*hooks\s*=\s*true\b/.test(l))) return { content, changed: false };
    if (table.some((l) => /^\s*hooks\s*=\s*false\b/.test(l))) {
      throw new Error(`config.toml sets 'hooks = false' explicitly — not overriding it. Enable hooks manually:\n${MANUAL_SNIPPET}`);
    }
    if (table.some((l) => /^\s*hooks\s*=/.test(l))) {
      throw new Error(`config.toml has an unrecognized 'hooks =' setting under [features] — edit it manually:\n${MANUAL_SNIPPET}`);
    }
    const next = [...lines.slice(0, range.start + 1), OUR_LINE, ...lines.slice(range.start + 1)];
    return { content: next.join("\n"), changed: true };
  }
  const block = [BLOCK_START, "[features]", "hooks = true", BLOCK_END, ""].join("\n");
  const base = content === "" || content.endsWith("\n") ? content : `${content}\n`;
  return { content: `${base}${base === "" ? "" : "\n"}${block}`, changed: true };
}

export function disableHooksFeature(content: string): TomlEdit {
  let changed = false;
  let out = content;
  // 1) whole managed block
  const blockRe = new RegExp(`\\n?${BLOCK_START}[\\s\\S]*?${BLOCK_END}\\n?`, "g");
  if (blockRe.test(out)) {
    out = out.replace(blockRe, "\n");
    changed = true;
  }
  // 2) our single line inside a shared [features] table
  const lines = out.split("\n");
  const kept = lines.filter((l) => l.trim() !== OUR_LINE);
  if (kept.length !== lines.length) {
    out = kept.join("\n");
    changed = true;
  }
  return { content: changed ? out.replace(/\n{3,}/g, "\n\n") : content, changed };
}
