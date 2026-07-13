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

// Minimal glob matcher for path allowlists: `**` crosses directories, `*`
// stays within one segment, `?` matches one character. Anchored on both ends.
// `caseInsensitive` is used for sensitive-file matching so `.ENV` / `ID_RSA`
// can't evade the deny on case-insensitive filesystems (macOS/Windows).
export function pathMatchesGlob(path: string, glob: string, caseInsensitive = false): boolean {
  let re = "";
  let i = 0;
  while (i < glob.length) {
    const c = glob[i]!;
    if (c === "*") {
      if (glob[i + 1] === "*") {
        // `**/` matches any number of leading path SEGMENTS (incl. zero), so it
        // must end at a `/` boundary — `(?:.*/)?`, NOT `.*` (which would let
        // `**/.env` match `restored.env`). A trailing `**` matches anything.
        if (glob[i + 2] === "/") {
          re += "(?:.*/)?";
          i += 3;
        } else {
          re += ".*";
          i += 2;
        }
      } else {
        re += "[^/]*";
        i++;
      }
    } else if (c === "?") {
      re += "[^/]";
      i++;
    } else {
      re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
      i++;
    }
  }
  return new RegExp(`^(?:${re})$`, caseInsensitive ? "i" : "").test(path);
}

export function isAllowedPath(path: string | undefined, allowlist: UserAllowlist | undefined): boolean {
  if (!path || !allowlist?.paths?.length) return false;
  return allowlist.paths.some((g) => pathMatchesGlob(path, g));
}
