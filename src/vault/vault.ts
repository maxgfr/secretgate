import { randomBytes } from "node:crypto";
import { closeSync, mkdirSync, openSync, readFileSync, renameSync, statSync, unlinkSync, writeSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { placeholderFor } from "./placeholder.js";

// The vault holds placeholder -> secret mappings in ~/.secretgate/vault.json.
// Secrets it stores were already on the user's disk in cleartext (.env files,
// pasted prompts) — the vault adds no new exposure, but it is still created
// 0700/0600 and its listing API never returns the secret values.

export interface VaultEntry {
  secret: string;
  ruleId: string;
  firstSeen: string;
  sources: string[];
}

export interface VaultListing {
  placeholder: string;
  ruleId: string;
  firstSeen: string;
  sources: string[];
}

interface VaultFile {
  version: 1;
  entries: Record<string, VaultEntry>;
}

export function defaultVaultHome(): string {
  return process.env.SECRETGATE_HOME ?? join(homedir(), ".secretgate");
}

// Write with the final permissions from the very first byte: open(mode) then
// write — never write-then-chmod. Renamed into place for atomicity.
function writeFileAtomic(path: string, content: string, mode: number): void {
  const tmp = `${path}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
  const fd = openSync(tmp, "w", mode);
  try {
    writeSync(fd, content);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, path);
}

const LOCK_WAIT_MS = 3000;
const LOCK_STALE_MS = 10_000;
const sleeper = new Int32Array(new SharedArrayBuffer(4));

// Hooks run as separate processes, several at once when tool calls overlap.
// A read-merge-write without a lock lets the last rename win and silently
// drops the other process's mapping — whose placeholder would then be written
// to disk unrestored. An O_EXCL lock file serialises the cycle; a lock left
// by a killed process is taken over once stale. On timeout it throws, and the
// hook fails closed.
function withLock<T>(lockPath: string, fn: () => T): T {
  const deadline = Date.now() + LOCK_WAIT_MS;
  let fd: number | undefined;
  while (fd === undefined) {
    try {
      fd = openSync(lockPath, "wx", 0o600);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      try {
        if (Date.now() - statSync(lockPath).mtimeMs > LOCK_STALE_MS) unlinkSync(lockPath);
      } catch {
        // released or taken over in between: retry
      }
      if (Date.now() > deadline) throw new Error("vault is locked by another secretgate process");
      Atomics.wait(sleeper, 0, 0, 5);
    }
  }
  try {
    return fn();
  } finally {
    closeSync(fd);
    try {
      unlinkSync(lockPath);
    } catch {
      // already gone
    }
  }
}

export class Vault {
  private readonly home: string;
  private readonly vaultPath: string;
  private saltValue: string | undefined;

  constructor(home: string = defaultVaultHome()) {
    this.home = home;
    this.vaultPath = join(home, "vault.json");
  }

  private ensureHome(): void {
    mkdirSync(this.home, { recursive: true, mode: 0o700 });
  }

  private salt(): string {
    if (this.saltValue) return this.saltValue;
    this.ensureHome();
    const saltPath = join(this.home, "salt");
    try {
      this.saltValue = readFileSync(saltPath, "utf8").trim();
    } catch {
      this.saltValue = randomBytes(32).toString("hex");
      writeFileAtomic(saltPath, this.saltValue, 0o600);
    }
    if (!this.saltValue) throw new Error(`empty salt file: ${saltPath}`);
    return this.saltValue;
  }

  private read(): VaultFile {
    try {
      const parsed = JSON.parse(readFileSync(this.vaultPath, "utf8")) as VaultFile;
      if (parsed && parsed.version === 1 && parsed.entries) return parsed;
    } catch {
      // missing or corrupt -> start fresh (corrupt vault must never break a hook)
    }
    return { version: 1, entries: {} };
  }

  // A read-merge-write cycle under the vault lock, so concurrent hook
  // processes (tool calls in flight) never drop each other's entries.
  recordSecret(secret: string, ruleId: string, source: string): string {
    this.ensureHome();
    return withLock(`${this.vaultPath}.lock`, () => this.recordLocked(secret, ruleId, source));
  }

  private recordLocked(secret: string, ruleId: string, source: string): string {
    const salt = this.salt();
    const file = this.read();
    // Collision handling: lengthen the placeholder until it's free or ours.
    let placeholder = "";
    for (const hexLen of [12, 16]) {
      placeholder = placeholderFor(secret, salt, hexLen);
      const existing = file.entries[placeholder];
      if (!existing || existing.secret === secret) break;
    }
    const entry = file.entries[placeholder];
    if (entry && entry.secret === secret) {
      if (!entry.sources.includes(source)) {
        entry.sources.push(source);
        writeFileAtomic(this.vaultPath, JSON.stringify(file, null, 2), 0o600);
      }
      return placeholder;
    }
    file.entries[placeholder] = { secret, ruleId, firstSeen: new Date().toISOString(), sources: [source] };
    writeFileAtomic(this.vaultPath, JSON.stringify(file, null, 2), 0o600);
    return placeholder;
  }

  secretFor(placeholder: string): string | undefined {
    return this.read().entries[placeholder]?.secret;
  }

  list(): VaultListing[] {
    return Object.entries(this.read().entries).map(([placeholder, e]) => ({
      placeholder,
      ruleId: e.ruleId,
      firstSeen: e.firstSeen,
      sources: e.sources,
    }));
  }

  clear(): void {
    this.ensureHome();
    withLock(`${this.vaultPath}.lock`, () => writeFileAtomic(this.vaultPath, JSON.stringify({ version: 1, entries: {} }, null, 2), 0o600));
  }
}
