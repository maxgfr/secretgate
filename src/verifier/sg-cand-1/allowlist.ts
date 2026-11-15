import { createHash } from "node:crypto";

// User-managed allowlist (distinct from the upstream per-rule allowlists baked
// into rules.gen.ts). Values are stored as SHA-256 hashes — the allowlist file
// never contains a raw secret.
export interface UserAllowlist {
  sha256?: string[];
  rules?: string[];
  paths?: string[];
}

export function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function isAllowedValue(secret: string, allowlist: UserAllowlist | undefined): boolean {
  if (!allowlist?.sha256?.length) return false;
  const h = sha256(secret);
  return allowlist.sha256.includes(h);
}

export function isDisabledRule(ruleId: string, allowlist: UserAllowlist | undefined): boolean {
  return allowlist?.rules?.includes(ruleId) ?? false;
}

type GlobToken = { t: "lit"; c: string } | { t: "one" } | { t: "star" } | { t: "any" } | { t: "segments" };

const SEQUENCE = /^(?:(-?\d+)\.\.(-?\d+)|([A-Za-z])\.\.([A-Za-z]))(?:\.\.(-?\d+))?$/;

// `{1..3}`, `{a..e}`, `{0..10..5}` as bash expands them (zero padding aside);
// undefined when `inner` is not a sequence.
function sequence(inner: string, limit: number): string[] | undefined {
  const m = SEQUENCE.exec(inner);
  if (!m) return undefined;
  const numeric = m[1] !== undefined;
  const from = numeric ? Number(m[1]) : m[3]!.charCodeAt(0);
  const to = numeric ? Number(m[2]) : m[4]!.charCodeAt(0);
  const step = Math.abs(Number(m[5] ?? 1)) || 1;
  const dir = from <= to ? 1 : -1;
  const out: string[] = [];
  for (let v = from; dir > 0 ? v <= to : v >= to; v += dir * step) {
    out.push(numeric ? String(v) : String.fromCharCode(v));
    if (out.length > limit) break;
  }
  return out;
}

/**
 * Brace expansion: `{a,b}` alternatives, and with `sequences` the bash ranges
 * `{1..3}` / `{a..c}` (globs keep those literal). A group with neither stays
 * literal, as in the shell. At most `limit + 1` results, so a caller can tell
 * an expansion that was cut short from one that fit.
 */
export function expandBraces(text: string, opts: { limit?: number; sequences?: boolean } = {}): string[] {
  const limit = opts.limit ?? 64;
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
  let alternatives: string[];
  if (commas.length > 0) {
    const bounds = [open, ...commas, close];
    alternatives = bounds.slice(0, -1).map((b, k) => text.slice(b + 1, bounds[k + 1]));
  } else {
    const seq = opts.sequences ? sequence(text.slice(open + 1, close), limit) : undefined;
    // No comma and no sequence: a literal brace.
    if (!seq) return expandBraces(tail, opts).map((t) => text.slice(0, close + 1) + t);
    alternatives = seq;
  }
  const out: string[] = [];
  for (const alt of alternatives) {
    for (const t of expandBraces(`${head}${alt}${tail}`, opts)) {
      out.push(t);
      if (out.length > limit) return out;
    }
  }
  return out;
}

function tokenizeGlob(glob: string): GlobToken[] {
  const tokens: GlobToken[] = [];
  for (let i = 0; i < glob.length; ) {
    const c = glob[i]!;
    if (c === "*" && glob[i + 1] === "*") {
      // `**/` matches any number of leading path SEGMENTS (incl. zero), so it
      // must end at a `/` boundary — NOT "anything" (which would let `**/.env`
      // match `restored.env`). A `**` elsewhere matches anything.
      if (glob[i + 2] === "/") {
        tokens.push({ t: "segments" });
        i += 3;
      } else {
        tokens.push({ t: "any" });
        i += 2;
      }
    } else if (c === "*") {
      tokens.push({ t: "star" });
      i++;
    } else if (c === "?") {
      tokens.push({ t: "one" });
      i++;
    } else {
      tokens.push({ t: "lit", c });
      i++;
    }
  }
  return tokens;
}

// Dynamic programming over (token, position): O(tokens × path) whatever the
// glob. A regex translation backtracks exponentially on `**a**a**a**b`, and
// scope globs come from the repository — a crafted one must not be able to
// stall a hook into its fail-open timeout.
function matchTokens(tokens: GlobToken[], path: string): boolean {
  const n = path.length;
  let next = new Uint8Array(n + 2);
  let cur = new Uint8Array(n + 2);
  next[n] = 1; // no tokens left: only the end of the path matches
  for (let i = tokens.length - 1; i >= 0; i--) {
    const tok = tokens[i]!;
    cur.fill(0);
    // `**/`: is there a k >= j with path[k] === "/" whose rest matches?
    let slashAhead = 0;
    for (let j = n; j >= 0; j--) {
      const ch = path[j];
      switch (tok.t) {
        case "lit":
          cur[j] = j < n && ch === tok.c ? next[j + 1]! : 0;
          break;
        case "one":
          cur[j] = j < n && ch !== "/" ? next[j + 1]! : 0;
          break;
        case "star":
          cur[j] = next[j] || (j < n && ch !== "/" ? cur[j + 1]! : 0);
          break;
        case "any":
          cur[j] = next[j] || (j < n ? cur[j + 1]! : 0);
          break;
        case "segments":
          if (j < n && ch === "/" && next[j + 1]) slashAhead = 1;
          cur[j] = next[j] || slashAhead;
          break;
      }
    }
    [next, cur] = [cur, next];
  }
  return next[0] === 1;
}

// Tokenized globs, keyed by flags + pattern: a hook checks the same few globs
// against every path of every tool call.
const GLOB_CACHE = new Map<string, GlobToken[][]>();

// Minimal glob matcher for path allowlists: `**` crosses directories, `*`
// stays within one segment, `?` matches one character, `{a,b}` is an
// alternation. Anchored on both ends. `caseInsensitive` is used for
// sensitive-file matching so `.ENV` / `ID_RSA` can't evade the deny on
// case-insensitive filesystems (macOS/Windows).
export function pathMatchesGlob(path: string, glob: string, caseInsensitive = false): boolean {
  const key = `${caseInsensitive ? "i" : "s"}${glob}`;
  let alternatives = GLOB_CACHE.get(key);
  if (!alternatives) {
    // A trailing `/**` also matches the directory itself (`src/**` ~ `src`), as
    // in picomatch/minimatch — checked by the differential test.
    const expanded = expandBraces(caseInsensitive ? glob.toLowerCase() : glob)
      .slice(0, 64)
      .flatMap((g) => (g.endsWith("/**") ? [g, g.slice(0, -3)] : [g]));
    alternatives = expanded.map(tokenizeGlob);
    if (GLOB_CACHE.size > 512) GLOB_CACHE.clear();
    GLOB_CACHE.set(key, alternatives);
  }
  const subject = caseInsensitive ? path.toLowerCase() : path;
  return alternatives.some((tokens) => matchTokens(tokens, subject));
}

export function isAllowedPath(path: string | undefined, allowlist: UserAllowlist | undefined): boolean {
  if (!path || !allowlist?.paths?.length) return false;
  return allowlist.paths.some((g) => pathMatchesGlob(path, g));
}
