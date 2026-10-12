// Targeted edits to Codex's ~/.codex/config.toml WITHOUT a TOML parser at
// runtime (the shipped bundle stays dependency-free, and a full parse/reprint
// would reorder/reformat the user's file). The feature gate can be spelled
// several ways, and each is edited where it lives:
//   - no features at all          -> append a clearly delimited managed block
//   - a `[features]` table        -> insert `hooks = true # secretgate` inside it
//   - root `features.x = …` keys  -> add `features.hooks = true # secretgate`
//   - root `features = { … }`     -> append `hooks = true` inside, marked
// A second `[features]` table is never written: TOML rejects a table defined
// twice, and Codex would refuse the whole file. Anything ambiguous -> throw
// with the exact manual snippet. Line endings are kept as found.

const BLOCK_START = "# >>> secretgate managed >>>";
const BLOCK_END = "# <<< secretgate managed <<<";
const OUR_LINE = "hooks = true # secretgate";
const OUR_DOTTED = "features.hooks = true # secretgate";
const INLINE_MARK = "# secretgate: hooks";

export interface TomlEdit {
  content: string;
  changed: boolean;
}

export interface HookTrustEntry {
  key: string;
  trustedHash: string;
}

const MANUAL_SNIPPET = `[features]\nhooks = true`;

const FEATURES_HEADER = /^\s*\[\s*features\s*\]\s*(?:#.*)?$/;
const TABLE_HEADER = /^\s*\[/;
const ROOT_DOTTED = /^\s*(?:features|"features")\s*\.\s*([A-Za-z0-9_-]+|"[^"]*")\s*=\s*(.*)$/;
const ROOT_INLINE = /^(\s*(?:features|"features")\s*=\s*\{)(.*)\}\s*(#.*)?$/;
const HOOKS_KEY = /(?:^|,)\s*hooks\s*=\s*(\S+?)\s*(?:,|$)/;

function splitLines(content: string): { lines: string[]; eol: string } {
  return { lines: content.split(/\r?\n/), eol: content.includes("\r\n") ? "\r\n" : "\n" };
}

function featuresTableRange(lines: string[]): { start: number; end: number } | undefined {
  const start = lines.findIndex((l) => FEATURES_HEADER.test(l));
  if (start === -1) return undefined;
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i++) {
    if (TABLE_HEADER.test(lines[i]!)) {
      end = i;
      break;
    }
  }
  return { start, end };
}

/** Index of the first table header: keys before it belong to the root table. */
function rootEnd(lines: string[]): number {
  const i = lines.findIndex((l) => TABLE_HEADER.test(l));
  return i === -1 ? lines.length : i;
}

const unquote = (k: string): string => (k.startsWith('"') ? k.slice(1, -1) : k);

function refuseValue(value: string, snippet: string): never {
  if (/^false\b/.test(value)) throw new Error(`config.toml sets 'hooks = false' explicitly — not overriding it. Enable hooks manually:\n${snippet}`);
  throw new Error(`config.toml has an unrecognized 'hooks =' feature setting — edit it manually:\n${snippet}`);
}

export function enableHooksFeature(content: string): TomlEdit {
  const { lines, eol } = splitLines(content);
  const range = featuresTableRange(lines);
  if (range) {
    const table = lines.slice(range.start + 1, range.end);
    if (table.some((l) => /^\s*hooks\s*=\s*true\b/.test(l))) return { content, changed: false };
    if (table.some((l) => /^\s*hooks\s*=\s*false\b/.test(l))) refuseValue("false", MANUAL_SNIPPET);
    if (table.some((l) => /^\s*hooks\s*=/.test(l))) refuseValue("?", MANUAL_SNIPPET);
    const next = [...lines.slice(0, range.start + 1), OUR_LINE, ...lines.slice(range.start + 1)];
    return { content: next.join(eol), changed: true };
  }
  const root = lines.slice(0, rootEnd(lines));
  // `features.web_search = true` at the root: the table already exists, as dotted keys.
  const dotted = root.map((l, i) => ({ i, m: ROOT_DOTTED.exec(l) })).filter((d) => d.m);
  if (dotted.length > 0) {
    const hooks = dotted.find((d) => unquote(d.m![1]!) === "hooks");
    if (hooks) {
      if (/^true\b/.test(hooks.m![2]!)) return { content, changed: false };
      refuseValue(hooks.m![2]!, "features.hooks = true");
    }
    const last = dotted[dotted.length - 1]!.i;
    return { content: [...lines.slice(0, last + 1), OUR_DOTTED, ...lines.slice(last + 1)].join(eol), changed: true };
  }
  // `features = { web_search = true }` at the root: extend it in place.
  const inlineAt = root.findIndex((l) => ROOT_INLINE.test(l));
  if (inlineAt !== -1) {
    const [, head, body, comment] = ROOT_INLINE.exec(lines[inlineAt]!)!;
    const hooks = HOOKS_KEY.exec(body!);
    if (hooks) {
      if (/^true$/.test(hooks[1]!)) return { content, changed: false };
      refuseValue(hooks[1]!, "features = { …, hooks = true }");
    }
    if (comment !== undefined) {
      throw new Error(
        `config.toml declares features as a commented inline table — add hooks to it manually:\n${lines[inlineAt]!.replace(/\}\s*#.*$/, "")}${body!.trim() ? ", " : ""}hooks = true }`,
      );
    }
    const items = body!.trim();
    lines[inlineAt] = `${head} ${items}${items ? ", " : ""}hooks = true } ${INLINE_MARK}`;
    return { content: lines.join(eol), changed: true };
  }
  const block = [BLOCK_START, "[features]", "hooks = true", BLOCK_END, ""].join(eol);
  const base = content === "" || content.endsWith("\n") ? content : `${content}${eol}`;
  return { content: `${base}${base === "" ? "" : eol}${block}`, changed: true };
}

/** Is the hooks feature on, whichever way config.toml spells it? */
export function hooksFeatureEnabled(content: string): boolean {
  const { lines } = splitLines(content);
  const range = featuresTableRange(lines);
  if (range && lines.slice(range.start + 1, range.end).some((l) => /^\s*hooks\s*=\s*true\b/.test(l))) return true;
  const root = lines.slice(0, rootEnd(lines));
  if (root.some((l) => /^\s*(?:features|"features")\s*\.\s*(?:hooks|"hooks")\s*=\s*true\b/.test(l))) return true;
  return root.some((l) => {
    const m = ROOT_INLINE.exec(l);
    return m !== null && HOOKS_KEY.exec(m[2]!)?.[1] === "true";
  });
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

function removeManagedBlocks(lines: string[]): { lines: string[]; changed: boolean } {
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

  return { lines: changed ? kept : lines, changed };
}

export function disableHooksFeature(content: string): TomlEdit {
  const { lines, eol } = splitLines(content);
  const managed = removeManagedBlocks(lines);
  let changed = managed.changed;
  const kept: string[] = [];
  for (const line of managed.lines) {
    // Our single line inside a shared [features] table, or among dotted keys.
    if (line.trim() === OUR_LINE || line.trim() === OUR_DOTTED) {
      changed = true;
      continue;
    }
    // Our addition to an inline table.
    const m = ROOT_INLINE.exec(line);
    if (m && m[3]?.trim() === INLINE_MARK) {
      const items = m[2]!
        .split(",")
        .map((s) => s.trim())
        .filter((s) => s !== "" && !/^hooks\s*=\s*true$/.test(s));
      kept.push(`${m[1]} ${items.join(", ")}${items.length > 0 ? " " : ""}}`);
      changed = true;
      continue;
    }
    kept.push(line);
  }
  return { content: changed ? kept.join(eol).replace(eol === "\r\n" ? /(?:\r\n){3,}/g : /\n{3,}/g, eol + eol) : content, changed };
}

function hookStateHeader(key: string): string {
  return `[hooks.state.${JSON.stringify(key)}]`;
}

function exactTableRange(lines: string[], header: string): { start: number; end: number } | undefined {
  const start = lines.findIndex((line) => line.trim() === header);
  if (start === -1) return undefined;
  let end = lines.length;
  for (let index = start + 1; index < lines.length; index++) {
    if (TABLE_HEADER.test(lines[index]!)) {
      end = index;
      break;
    }
  }
  return { start, end };
}

export function upsertHookTrust(content: string, entries: HookTrustEntry[]): TomlEdit {
  const eol = content.includes("\r\n") ? "\r\n" : "\n";
  let out = content;
  let changed = false;

  for (const entry of entries) {
    const header = hookStateHeader(entry.key);
    const trustedLine = `trusted_hash = ${JSON.stringify(entry.trustedHash)}`;
    const lines = out.split(/\r?\n/);
    const range = exactTableRange(lines, header);

    if (!range) {
      const base = out === "" || out.endsWith("\n") ? out : `${out}${eol}`;
      out = `${base}${base === "" ? "" : eol}${header}${eol}${trustedLine}${eol}`;
      changed = true;
      continue;
    }

    const trustedOffset = lines.slice(range.start + 1, range.end).findIndex((line) => /^\s*trusted_hash\s*=/.test(line));
    if (trustedOffset === -1) {
      lines.splice(range.start + 1, 0, trustedLine);
      out = lines.join(eol);
      changed = true;
      continue;
    }

    const trustedIndex = range.start + 1 + trustedOffset;
    if (lines[trustedIndex]!.trim() !== trustedLine) {
      lines[trustedIndex] = trustedLine;
      out = lines.join(eol);
      changed = true;
    }
  }

  return { content: out, changed };
}

export function removeHookTrust(content: string, keys: string[]): TomlEdit {
  const eol = content.includes("\r\n") ? "\r\n" : "\n";
  let out = content;
  let changed = false;

  for (const key of keys) {
    const lines = out.split(/\r?\n/);
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
    out = lines.join(eol).replace(eol === "\r\n" ? /(?:\r\n){3,}/g : /\n{3,}/g, eol + eol);
    changed = true;
  }

  return { content: out, changed };
}

/**
 * Trust entries for `hooksPath` that carry one of `hashes` (secretgate's own
 * hooks) under a key other than those in `keep`: left behind when another
 * tool reordered hooks.json, or by an older install. Codex would keep them
 * forever, and our hooks at their new position would be untrusted.
 */
export function staleHookTrustKeys(content: string, hooksPath: string, hashes: Set<string>, keep: Set<string>): string[] {
  const lines = content.split(/\r?\n/);
  const stale: string[] = [];
  for (let i = 0; i < lines.length; i++) {
    const m = /^\s*\[hooks\.state\.("(?:[^"\\]|\\.)*")\]\s*$/.exec(lines[i]!);
    if (!m) continue;
    let key: string;
    try {
      key = JSON.parse(m[1]!) as string;
    } catch {
      continue;
    }
    if (!key.startsWith(`${hooksPath}:`) || keep.has(key)) continue;
    for (let j = i + 1; j < lines.length && !TABLE_HEADER.test(lines[j]!); j++) {
      const h = /^\s*trusted_hash\s*=\s*("(?:[^"\\]|\\.)*")/.exec(lines[j]!);
      if (h && hashes.has(JSON.parse(h[1]!) as string)) stale.push(key);
    }
  }
  return stale;
}
