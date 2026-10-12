import { randomBytes } from "node:crypto";
import { closeSync, openSync, renameSync, rmSync, writeSync } from "node:fs";

// Write with the final permissions from the very first byte — open(mode) then
// write, never write-then-chmod — and rename into place, so a reader (a hook in
// another process) sees the old file or the new one, never half of either. The
// temporary name is random and created exclusively; on any failure it is
// removed rather than left next to the target.
export function writeFileAtomic(path: string, content: string, mode = 0o644): void {
  const tmp = `${path}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
  const fd = openSync(tmp, "wx", mode);
  try {
    try {
      writeSync(fd, content);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, path);
  } catch (err) {
    rmSync(tmp, { force: true });
    throw err;
  }
}
