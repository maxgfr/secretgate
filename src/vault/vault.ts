import { randomBytes } from "node:crypto";
import { chmodSync, closeSync, mkdirSync, openSync, readFileSync, renameSync, statSync, unlinkSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { writeFileAtomic } from "../fs-atomic.js";
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

/** One secret to record, and where it was seen. */
export interface SecretRecord {
  secret: string;
  ruleId: string;
  source: string;
}

export function defaultVaultHome(): string {
  return process.env.SECRETGATE_HOME ?? join(homedir(), ".secretgate");
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

  // A missing vault is an empty one. An unreadable or malformed one is too —
  // a corrupt vault must never break a hook — but it is reported, so the next
  // write can set it aside instead of silently replacing every mapping in it.
  private read(): { file: VaultFile; corrupt: boolean } {
    let raw: string;
    try {
      raw = readFileSync(this.vaultPath, "utf8");
    } catch {
      return { file: { version: 1, entries: {} }, corrupt: false };
    }
    try {
      const parsed = JSON.parse(raw) as VaultFile;
      if (parsed && parsed.version === 1 && parsed.entries && typeof parsed.entries === "object") return { file: parsed, corrupt: false };
    } catch {
      // fall through
    }
    return { file: { version: 1, entries: {} }, corrupt: true };
  }

  // Keep the unreadable file (it may hold the only copy of mappings still in
  // use) under a name nothing reads, before a fresh vault takes its place.
  private setAside(): void {
    const aside = `${this.vaultPath}.corrupt-${new Date().toISOString().replaceAll(/[:.]/g, "-")}-${randomBytes(2).toString("hex")}`;
    renameSync(this.vaultPath, aside);
    chmodSync(aside, 0o600);
  }

  // A read-merge-write cycle under the vault lock, so concurrent hook
  // processes (tool calls in flight) never drop each other's entries.
  recordSecret(secret: string, ruleId: string, source: string): string {
    return this.recordSecrets([{ secret, ruleId, source }])[0]!;
  }

  /** Record many secrets in ONE locked read-merge-write cycle (a tool output
   *  can carry thousands); returns their placeholders, in order. */
  recordSecrets(items: SecretRecord[]): string[] {
    if (items.length === 0) return [];
    this.ensureHome();
    return withLock(`${this.vaultPath}.lock`, () => {
      const salt = this.salt();
      const { file, corrupt } = this.read();
      let dirty = false;
      const placeholders = items.map(({ secret, ruleId, source }) => {
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
            dirty = true;
          }
        } else {
          file.entries[placeholder] = { secret, ruleId, firstSeen: new Date().toISOString(), sources: [source] };
          dirty = true;
        }
        return placeholder;
      });
      if (dirty) {
        if (corrupt) this.setAside();
        writeFileAtomic(this.vaultPath, JSON.stringify(file, null, 2), 0o600);
      }
      return placeholders;
    });
  }

  secretFor(placeholder: string): string | undefined {
    return this.lookup()(placeholder);
  }

  /** A placeholder → secret resolver over ONE read of the vault, for callers
   *  that resolve many placeholders at once. */
  lookup(): (placeholder: string) => string | undefined {
    const { entries } = this.read().file;
    return (placeholder) => (Object.hasOwn(entries, placeholder) ? entries[placeholder]?.secret : undefined);
  }

  list(): VaultListing[] {
    return Object.entries(this.read().file.entries).map(([placeholder, e]) => ({
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
