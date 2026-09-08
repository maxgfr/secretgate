import { createHash } from "node:crypto";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { defaultVaultHome } from "../vault/vault.js";

function stoppedPath(session: string): string {
  return join(defaultVaultHome(), "stopped-sessions", createHash("sha256").update(session).digest("hex"));
}

export function isStoppedSession(session: unknown): boolean {
  return typeof session === "string" && existsSync(stoppedPath(session));
}

// An unsupported PostToolUse result may remain in the local transcript after
// continue:false. Prevent a later prompt from sending that transcript onward.
export function stopSession(session: unknown): void {
  if (typeof session !== "string" || !session) return;
  mkdirSync(join(defaultVaultHome(), "stopped-sessions"), { recursive: true, mode: 0o700 });
  writeFileSync(stoppedPath(session), "unscannable tool result\n", { mode: 0o600 });
}
