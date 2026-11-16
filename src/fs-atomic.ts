import { randomBytes } from "node:crypto";
import { closeSync, openSync, realpathSync, renameSync, rmSync, statSync, writeSync } from "node:fs";

// Write with the final permissions from the very first byte — open(mode) then
// write, never write-then-chmod — and rename into place, so a reader (a hook in
// another process) sees the old file or the new one, never half of either. The
// temporary name is random and created exclusively; on any failure it is
// removed rather than left next to the target.
export function writeFileAtomic(path: string, content: string | Uint8Array, mode = 0o644): void {
  const tmp = `${path}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
  const fd = openSync(tmp, "wx", mode);
  try {
    try {
      if (typeof content === "string") writeSync(fd, content);
      // A write can be short: loop until every byte is out.
      else for (let at = 0; at < content.length; ) at += writeSync(fd, content, at, content.length - at);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, path);
  } catch (err) {
    rmSync(tmp, { force: true });
    throw err;
  }
}

// Rewrite a file that belongs to the USER (an agent's settings): it keeps its
// permission bits — a settings file can hold API keys behind 0600, and a
// rewrite at 0644 would open it to every account on the machine — and a
// symlink (a dotfiles checkout) is written through, not replaced by a copy the
// checkout no longer sees. `mode` is for a file that does not exist yet. The
// bits can only be narrowed by the umask, never widened.
export function rewriteFileAtomic(path: string, content: string, mode = 0o644): void {
  let target = path;
  let keep = mode;
  try {
    target = realpathSync(path);
    keep = statSync(target).mode & 0o777;
  } catch {
    // Nothing there (or a dangling link): a new file, at `path`.
  }
  writeFileAtomic(target, content, keep);
}
