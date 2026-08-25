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

export interface HookTrustEntry {
  key: string;
  trustedHash: string;
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

function removeLegacyHookLine(lines: string[]): string[] {
  const range = featuresTableRange(lines);
  if (!range) return lines;

  const hookOffset = lines.slice(range.start + 1, range.end).findIndex((line) => /^\s*hooks\s*=\s*true\s*(#.*)?$/.test(line));
  if (hookOffset === -1) return lines;

  const hookIndex = range.start + 1 + hookOffset;
  const withoutHook = [...lines.slice(0, hookIndex), ...lines.slice(hookIndex + 1)];
  const updatedRange = featuresTableRange(withoutHook);
  if (!updatedRange) return withoutHook;

  const tableIsEmpty = withoutHook.slice(updatedRange.start + 1, updatedRange.end).every((line) => line.trim() === "");
  if (!tableIsEmpty) return withoutHook;

  return [...withoutHook.slice(0, updatedRange.start), ...withoutHook.slice(updatedRange.end)];
}

function removeManagedBlocks(content: string): TomlEdit {
  const lines = content.split("\n");
  const kept: string[] = [];
  let changed = false;

  for (let i = 0; i < lines.length; i++) {
    if (lines[i]?.trim() !== BLOCK_START) {
      kept.push(lines[i]!);
      continue;
    }

    const end = lines.findIndex((line, index) => index > i && line.trim() === BLOCK_END);
    if (end === -1) {
      kept.push(lines[i]!);
      continue;
    }

    kept.push(...removeLegacyHookLine(lines.slice(i + 1, end)));
    changed = true;
    i = end;
  }

  return { content: changed ? kept.join("\n") : content, changed };
}

export function disableHooksFeature(content: string): TomlEdit {
  const managed = removeManagedBlocks(content);
  let changed = managed.changed;
  let out = managed.content;
  // 2) our single line inside a shared [features] table
  const lines = out.split("\n");
  const kept = lines.filter((l) => l.trim() !== OUR_LINE);
  if (kept.length !== lines.length) {
    out = kept.join("\n");
    changed = true;
  }
  return { content: changed ? out.replace(/\n{3,}/g, "\n\n") : content, changed };
}

function hookStateHeader(key: string): string {
  return `[hooks.state.${JSON.stringify(key)}]`;
}

function exactTableRange(lines: string[], header: string): { start: number; end: number } | undefined {
  const start = lines.findIndex((line) => line.trim() === header);
  if (start === -1) return undefined;
  let end = lines.length;
  for (let index = start + 1; index < lines.length; index++) {
    if (/^\s*\[/.test(lines[index]!)) {
      end = index;
      break;
    }
  }
  return { start, end };
}

export function upsertHookTrust(content: string, entries: HookTrustEntry[]): TomlEdit {
  let out = content;
  let changed = false;

  for (const entry of entries) {
    const header = hookStateHeader(entry.key);
    const trustedLine = `trusted_hash = ${JSON.stringify(entry.trustedHash)}`;
    const lines = out.split("\n");
    const range = exactTableRange(lines, header);

    if (!range) {
      const base = out === "" || out.endsWith("\n") ? out : `${out}\n`;
      out = `${base}${base === "" ? "" : "\n"}${header}\n${trustedLine}\n`;
      changed = true;
      continue;
    }

    const trustedOffset = lines.slice(range.start + 1, range.end).findIndex((line) => /^\s*trusted_hash\s*=/.test(line));
    if (trustedOffset === -1) {
      lines.splice(range.start + 1, 0, trustedLine);
      out = lines.join("\n");
      changed = true;
      continue;
    }

    const trustedIndex = range.start + 1 + trustedOffset;
    if (lines[trustedIndex] !== trustedLine) {
      lines[trustedIndex] = trustedLine;
      out = lines.join("\n");
      changed = true;
    }
  }

  return { content: out, changed };
}

export function removeHookTrust(content: string, keys: string[]): TomlEdit {
  let out = content;
  let changed = false;

  for (const key of keys) {
    const lines = out.split("\n");
    const range = exactTableRange(lines, hookStateHeader(key));
    if (!range) continue;

    const body = lines.slice(range.start + 1, range.end);
    const keptBody = body.filter((line) => !/^\s*trusted_hash\s*=/.test(line));
    if (keptBody.length === body.length) continue;

    const hasOtherSettings = keptBody.some((line) => line.trim() !== "" && !/^\s*#/.test(line));
    if (hasOtherSettings) {
      lines.splice(range.start + 1, body.length, ...keptBody);
    } else {
      lines.splice(range.start, range.end - range.start);
    }
    out = lines.join("\n").replace(/\n{3,}/g, "\n\n");
    changed = true;
  }

  return { content: out, changed };
}
