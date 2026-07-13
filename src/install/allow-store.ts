import { randomBytes } from "node:crypto";
import { closeSync, mkdirSync, openSync, readFileSync, renameSync, writeSync } from "node:fs";
import { dirname } from "node:path";
import { allowlistPath } from "../config.js";
import type { UserAllowlist } from "../engine/allowlist.js";

// Additive writer for ~/.secretgate/allowlist.json (0600, atomic, read-merge-
// write so concurrent `allow` calls don't clobber each other).
export function writeAllow(add: UserAllowlist): UserAllowlist {
  const path = allowlistPath();
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  let current: UserAllowlist = {};
  try {
    current = JSON.parse(readFileSync(path, "utf8")) as UserAllowlist;
  } catch {
    // missing or corrupt -> start fresh
  }
  const merged: UserAllowlist = {
    sha256: [...new Set([...(current.sha256 ?? []), ...(add.sha256 ?? [])])],
    rules: [...new Set([...(current.rules ?? []), ...(add.rules ?? [])])],
    paths: [...new Set([...(current.paths ?? []), ...(add.paths ?? [])])],
  };
  const tmp = `${path}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
  const fd = openSync(tmp, "w", 0o600);
  try {
    writeSync(fd, JSON.stringify(merged, null, 2));
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, path);
  return merged;
}
