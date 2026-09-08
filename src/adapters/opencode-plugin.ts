import { loadConfig } from "../config.js";
import { disableState, recordSession } from "../disable.js";
import { commandTouchesSensitivePath, sensitivePathMatch } from "../paths.js";
import { restorePlaceholders } from "../redact.js";
import { Vault } from "../vault/vault.js";
import { eventRedactor, isBinaryField } from "../hooks/scan-budget.js";

// OpenCode plugin — bundled standalone as scripts/secretgate-opencode.mjs and
// installed into ~/.config/opencode/plugin/secretgate.js. OpenCode's hook
// contract honors IN-PLACE mutations of the objects it passes (verified in
// opencode's session/tools.ts): mutate `parts[i].text`, `output.args.<prop>`
// and `output.output` — never reassign whole objects. Unlike Claude Code,
// OpenCode lets us REWRITE the prompt, so secrets in prompts are redacted
// (not blocked) here.
//
// IMPORTANT: this module must export ONLY the plugin function. OpenCode treats
// EVERY named export as a plugin and rejects non-function exports with "Plugin
// export is not a function", so no version constants or helpers may be exported.

const ALLOW_TAG = "[allow-secret]";

// Mutate every string property of a container (object/array) in place.
function mutateStringsInPlace(container: any, fn: (s: string) => string): boolean {
  if (container === null || typeof container !== "object") return false;
  const pending: Array<() => void> = [];
  const stack = [container];
  const seen = new Set<object>();
  while (stack.length) {
    const current = stack.pop();
    if (seen.has(current)) continue;
    seen.add(current);
    for (const key of Object.keys(current)) {
      const value = current[key];
      // Preserve binary attachments; they are outside text scanning.
      if (isBinaryField(key, value, current)) continue;
      const mappedKey = fn(key);
      const mapped = typeof value === "string" ? fn(value) : value;
      if (mapped !== value || mappedKey !== key)
        pending.push(() => {
          if (mappedKey !== key) delete current[key];
          Object.defineProperty(current, mappedKey, { value: mapped, enumerable: true, configurable: true, writable: true });
        });
      if (value !== null && typeof value === "object") stack.push(value);
    }
  }
  for (const apply of pending) apply();
  return pending.length > 0;
}

const RESTORE_TOOLS = new Set(["write", "edit", "patch", "apply_patch", "multiedit"]);
const READ_TOOLS = new Set(["read", "grep"]);

// The plugin runs INSIDE the OpenCode process, so `SECRETGATE_DISABLE=1 opencode`
// reaches it the same way it reaches a spawned hook, and process.cwd() is the
// directory OpenCode was started in — the one `secretgate disable --project`
// records.
export const SecretgatePlugin = async (ctx: unknown) => {
  const directory = (ctx as { directory?: unknown } | undefined)?.directory;
  const cwd = typeof directory === "string" ? directory : process.cwd();
  const isOff = (sessionId?: unknown): boolean => disableState({ cwd, sessionId: typeof sessionId === "string" ? sessionId : undefined }).disabled;
  return {
    // OpenCode keeps rewritten args in tool history, including failed calls.
    // Redact that history immediately before it is converted to model messages.
    "experimental.chat.messages.transform": async (_input: unknown, output: { messages?: Array<{ info?: { sessionID?: string }; parts?: unknown[] }> }) => {
      for (const message of output.messages ?? []) {
        if (isOff(message.info?.sessionID)) continue;
        try {
          const cfg = loadConfig(cwd);
          const vault = new Vault();
          for (const part of message.parts ?? []) {
            // User text has already passed chat.message (including explicit bypass).
            if ((part as { type?: string })?.type === "tool") mutateStringsInPlace(part, eventRedactor(vault, "opencode:history", cfg.allowlist));
          }
        } catch {
          throw new Error("secretgate: tool history could not be scanned safely; start a fresh session.");
        }
      }
    },
    "chat.message": async (input: { sessionID?: unknown } | undefined, output: { message?: unknown; parts?: Array<{ text?: unknown }> }) => {
      const sessionID = input?.sessionID;
      recordSession(typeof sessionID === "string" ? sessionID : undefined, cwd);
      if (isOff(sessionID)) return;
      const parts = output?.parts;
      if (!Array.isArray(parts)) return;
      if (parts.some((p) => typeof p?.text === "string" && p.text.includes(ALLOW_TAG))) return;
      try {
        const cfg = loadConfig(cwd);
        const vault = new Vault();
        const redact = eventRedactor(vault, "opencode:prompt", cfg.allowlist);
        const mapped = parts.map((part) => (typeof part?.text === "string" ? redact(part.text) : undefined));
        parts.forEach((part, i) => {
          if (mapped[i] !== undefined) part.text = mapped[i];
        });
      } catch {
        throw new Error("secretgate: prompt could not be scanned safely; shorten it and retry.");
      }
    },

    "tool.execute.before": async (input: { tool?: string; sessionID?: unknown }, output: { args?: Record<string, any> }) => {
      const tool = String(input?.tool ?? "").toLowerCase();
      const args = output?.args ?? {};
      const cfg = loadConfig(cwd);
      // Disabled: skip the sensitive-path deny, but keep restoring placeholders
      // so a disabled run never writes a dead SECRETGATE_ token to disk.
      const off = isOff(input?.sessionID);
      if (!off && READ_TOOLS.has(tool)) {
        const target = typeof args.filePath === "string" ? args.filePath : typeof args.path === "string" ? args.path : undefined;
        const hit = target ? sensitivePathMatch(target, cfg.allowlist, cwd) : undefined;
        if (hit) {
          throw new Error(
            `secretgate: '${target}' looks sensitive (${hit}); its content must not enter the model. Allow it with \`secretgate allow --path '${target}'\` if this is intentional.`,
          );
        }
      }
      if (!off && tool === "bash" && typeof args.command === "string") {
        const touched = commandTouchesSensitivePath(args.command, cfg.allowlist, cwd);
        if (touched) {
          throw new Error(`secretgate: this command touches '${touched}', which looks sensitive; its content must not enter the model.`);
        }
      }
      const restoreThis = RESTORE_TOOLS.has(tool) || (tool === "bash" && cfg.restoreBash);
      if (restoreThis) {
        const vault = new Vault();
        mutateStringsInPlace(args, (s) => restorePlaceholders(s, vault).text);
      }
    },

    "tool.execute.after": async (
      input: { tool?: string; sessionID?: unknown },
      output: { title?: string; output?: string; metadata?: unknown; content?: unknown; structuredContent?: unknown; attachments?: unknown; isError?: boolean },
    ) => {
      if (isOff(input?.sessionID)) return;
      const tool = String(input?.tool ?? "").toLowerCase();
      try {
        const cfg = loadConfig(cwd);
        const vault = new Vault();
        mutateStringsInPlace(output, eventRedactor(vault, `opencode:${tool}`, cfg.allowlist));
      } catch {
        const notice = "[secretgate withheld this tool output: scan failed or output exceeded the scan budget]";
        if (!output || typeof output !== "object") throw new Error(notice);
        const mcp = "content" in output;
        for (const key of Object.keys(output)) delete (output as Record<string, unknown>)[key];
        if (mcp) {
          output.content = [{ type: "text", text: notice }];
          output.isError = true;
        } else {
          output.output = notice;
          output.title = "secretgate: output withheld";
          output.metadata = {};
        }
      }
    },
  };
};
