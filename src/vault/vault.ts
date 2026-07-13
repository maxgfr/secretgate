import { randomBytes } from "node:crypto";
import { closeSync, mkdirSync, openSync, readFileSync, renameSync, writeSync } from "node:fs";
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

  // recordSecret is a read-merge-write cycle so concurrent hook processes
  // (multiple tool calls in flight) don't clobber each other's entries.
  recordSecret(secret: string, ruleId: string, source: string): string {
    this.ensureHome();
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
    writeFileAtomic(this.vaultPath, JSON.stringify({ version: 1, entries: {} }, null, 2), 0o600);
  }
}
