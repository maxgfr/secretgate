import { loadConfig } from "../config.js";
import { commandTouchesSensitivePath, sensitivePathMatch } from "../paths.js";
import { redactText, restorePlaceholders } from "../redact.js";
import { Vault } from "../vault/vault.js";
import { VERSION } from "../version.js";

// OpenCode plugin — bundled standalone as scripts/secretgate-opencode.mjs and
// installed into ~/.config/opencode/plugin/secretgate.js (or as an npm plugin
// entry). OpenCode's hook contract honors IN-PLACE mutations of the objects it
// passes (verified in opencode's session/tools.ts): mutate `parts[i].text`,
// `output.args.<prop>` and `output.output` — never reassign whole objects.
// Unlike Claude Code, OpenCode lets us REWRITE the prompt, so secrets in
// prompts are redacted (not blocked) here.

const ALLOW_TAG = "[allow-secret]";

export const SECRETGATE_PLUGIN_VERSION = VERSION;

// Mutate every string property of a container (object/array) in place.
function mutateStringsInPlace(container: any, fn: (s: string) => string): boolean {
  if (container === null || typeof container !== "object") return false;
  let changed = false;
  for (const key of Object.keys(container)) {
    const v = container[key];
    if (typeof v === "string") {
      const mapped = fn(v);
      if (mapped !== v) {
        container[key] = mapped;
        changed = true;
      }
    } else if (v !== null && typeof v === "object") {
      if (mutateStringsInPlace(v, fn)) changed = true;
    }
  }
  return changed;
}

const RESTORE_TOOLS = new Set(["write", "edit", "patch", "multiedit"]);
const READ_TOOLS = new Set(["read", "grep"]);

export const SecretgatePlugin = async (_ctx: unknown) => {
  return {
    "chat.message": async (_input: unknown, output: { message?: unknown; parts?: Array<{ text?: unknown }> }) => {
      const parts = output?.parts;
      if (!Array.isArray(parts)) return;
      if (parts.some((p) => typeof p?.text === "string" && p.text.includes(ALLOW_TAG))) return;
      const cfg = loadConfig();
      const vault = new Vault();
      for (const part of parts) {
        if (typeof part?.text !== "string") continue;
        const r = redactText(part.text, vault, "opencode:prompt", { allowlist: cfg.allowlist });
        if (r.replaced.length > 0) part.text = r.text;
      }
    },

    "tool.execute.before": async (input: { tool?: string }, output: { args?: Record<string, any> }) => {
      const tool = String(input?.tool ?? "").toLowerCase();
      const args = output?.args ?? {};
      if (READ_TOOLS.has(tool)) {
        const target = typeof args.filePath === "string" ? args.filePath : typeof args.path === "string" ? args.path : undefined;
        const hit = target ? sensitivePathMatch(target) : undefined;
        if (hit) {
          throw new Error(
            `secretgate: '${target}' looks sensitive (${hit}); its content must not enter the model. Allow it with \`secretgate allow --path '${target}'\` if this is intentional.`,
          );
        }
      }
      if (tool === "bash" && typeof args.command === "string") {
        const touched = commandTouchesSensitivePath(args.command);
        if (touched) {
          throw new Error(`secretgate: this command touches '${touched}', which looks sensitive; its content must not enter the model.`);
        }
      }
      const cfg = loadConfig();
      const restoreThis = RESTORE_TOOLS.has(tool) || (tool === "bash" && cfg.restoreBash);
      if (restoreThis) {
        const vault = new Vault();
        mutateStringsInPlace(args, (s) => restorePlaceholders(s, vault).text);
      }
    },

    "tool.execute.after": async (input: { tool?: string }, output: { title?: string; output?: string; metadata?: unknown }) => {
      const tool = String(input?.tool ?? "").toLowerCase();
      const cfg = loadConfig();
      const vault = new Vault();
      const redact = (s: string) => redactText(s, vault, `opencode:${tool}`, { allowlist: cfg.allowlist }).text;
      if (typeof output?.output === "string") {
        const mapped = redact(output.output);
        if (mapped !== output.output) output.output = mapped;
      }
      if (typeof output?.title === "string") {
        const mapped = redact(output.title);
        if (mapped !== output.title) output.title = mapped;
      }
      if (output?.metadata !== null && typeof output?.metadata === "object") {
        mutateStringsInPlace(output.metadata, redact);
      }
    },
  };
};
