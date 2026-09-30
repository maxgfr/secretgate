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

// `{a,b}` → alternatives, expanded up front (bounded) so matching stays linear.
function expandGlobBraces(glob: string, limit = 64): string[] {
  const open = glob.indexOf("{");
  if (open === -1) return [glob];
  let depth = 0;
  const commas: number[] = [];
  let close = -1;
  for (let i = open; i < glob.length; i++) {
    const c = glob[i];
    if (c === "{") depth++;
    else if (c === "}" && --depth === 0) {
      close = i;
      break;
    } else if (c === "," && depth === 1) commas.push(i);
  }
  if (close === -1) return [glob];
  // No top-level comma: a literal brace, as in the shell.
  if (commas.length === 0) return expandGlobBraces(glob.slice(close + 1), limit).map((t) => glob.slice(0, close + 1) + t);
  const bounds = [open, ...commas, close];
  const out: string[] = [];
  for (let k = 0; k + 1 < bounds.length && out.length < limit; k++) {
    out.push(...expandGlobBraces(glob.slice(0, open) + glob.slice(bounds[k]! + 1, bounds[k + 1]) + glob.slice(close + 1), limit));
  }
  return out.slice(0, limit);
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
    const expanded = expandGlobBraces(caseInsensitive ? glob.toLowerCase() : glob).flatMap((g) => (g.endsWith("/**") ? [g, g.slice(0, -3)] : [g]));
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
