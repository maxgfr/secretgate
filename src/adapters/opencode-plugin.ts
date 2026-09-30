import { fileURLToPath } from "node:url";
import { loadConfig, type SecretgateConfig } from "../config.js";
import { disableState, recordSession } from "../disable.js";
import { preToolPolicy } from "../hooks/policy.js";
import { eventRedactor, isBinaryField } from "../hooks/scan-budget.js";
import { extractToolCall } from "../hooks/tool-call.js";
import { applyPromptDirective, promptDirective } from "../prompt-directive.js";
import { sensitivePathMatch } from "../paths.js";
import { restorePlaceholders } from "../redact.js";
import { accessViolation, filterSearchOutput, promptScopeViolation } from "../scope.js";
import { Vault } from "../vault/vault.js";

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

interface PromptPart {
  type?: string;
  text?: unknown;
  synthetic?: boolean;
  url?: unknown;
  filename?: unknown;
  mime?: unknown;
  source?: { path?: unknown };
}

// The file an attachment part inlines (an @mention), when it is a local file.
function attachedPath(part: PromptPart): string | undefined {
  if (typeof part.url === "string" && part.url.startsWith("file:")) {
    try {
      return fileURLToPath(part.url);
    } catch {
      return undefined;
    }
  }
  if (typeof part.source?.path === "string") return part.source.path;
  // Synthetic "Called the Read tool with the following input: {"filePath":…}".
  if (part.synthetic && typeof part.text === "string") return /"filePath":\s*"((?:[^"\\]|\\.)*)"/.exec(part.text)?.[1];
  return undefined;
}

// The plugin runs INSIDE the OpenCode process, so `SECRETGATE_DISABLE=1 opencode`
// reaches it the same way it reaches a spawned hook, and process.cwd() is the
// directory OpenCode was started in — the one `secretgate disable --project`
// records.
export const SecretgatePlugin = async (ctx: unknown) => {
  const directory = (ctx as { directory?: unknown } | undefined)?.directory;
  const cwd = typeof directory === "string" ? directory : process.cwd();
  const offState = (sessionId?: unknown) => disableState({ cwd, sessionId: typeof sessionId === "string" ? sessionId : undefined });
  const isOff = (sessionId?: unknown): boolean => offState(sessionId).disabled;
  const client = (ctx as { client?: { session?: { get?: (req: { path: { id: string } }) => Promise<{ data?: { parentID?: unknown } }> } } } | undefined)
    ?.client;
  // Fails SAFE: a session that cannot be looked up — no session API, or the
  // lookup fails — counts as a subsession, so the off switch is refused and
  // the user falls back to `secretgate disable` in a terminal. (Without a
  // session id nothing can be paused anyway.)
  const isSubsession = async (sessionId: unknown): Promise<boolean> => {
    if (typeof sessionId !== "string") return false;
    if (typeof client?.session?.get !== "function") return true;
    try {
      const res = await client.session.get({ path: { id: sessionId } });
      return typeof res?.data?.parentID === "string" && res.data.parentID.length > 0;
    } catch {
      return true;
    }
  };
  // Project config for this event; `disable --scope` lifts the scope too.
  const configFor = (sessionId?: unknown): SecretgateConfig => {
    const cfg = loadConfig(cwd);
    return offState(sessionId).includesScope ? { ...cfg, scopes: [], error: undefined } : cfg;
  };
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
    "chat.message": async (input: { sessionID?: unknown } | undefined, output: { message?: unknown; parts?: PromptPart[] }) => {
      const sessionID = input?.sessionID;
      recordSession(typeof sessionID === "string" ? sessionID : undefined, cwd);
      const parts = output?.parts;
      if (!Array.isArray(parts)) return;
      // "désactive secretgate" typed by the user pauses this session. OpenCode
      // has no user-facing hook message, so the confirmation rides along in
      // the prompt for the model to relay.
      const said = parts.find(
        (p) => typeof p?.text === "string" && !p.synthetic && (p.type === undefined || p.type === "text") && promptDirective(String(p.text)),
      );
      // A subagent's prompt is written by the model (TaskTool feeds it through
      // chat.message): only the user's own, top-level session may switch
      // secretgate off.
      if (said && (await isSubsession(sessionID))) {
        said.text = `${said.text}\n\n[secretgate: ignored an off-switch — this session could not be confirmed as your main session (a subagent prompt is written by the model). Run \`secretgate disable --session\` in a terminal instead]`;
      } else if (said) {
        const notice = applyPromptDirective(promptDirective(String(said.text))!, typeof sessionID === "string" ? sessionID : undefined, cwd);
        said.text = `${said.text}\n\n[${notice}]`;
      }
      const cfg = configFor(sessionID);
      // Scope first — it holds while secretgate is disabled. Out-of-scope
      // attachments are replaced by a note (OpenCode can rewrite the prompt).
      if (cfg.scopes.length > 0) {
        for (const part of parts) {
          if (!part || typeof part !== "object") continue;
          const path = attachedPath(part);
          const why = path ? cfg.scopes.map((s) => accessViolation(s, path, cwd, "read")).find(Boolean) : undefined;
          if (why) {
            for (const key of ["url", "filename", "mime", "source"] as const) delete part[key];
            part.type = "text";
            part.text = `[secretgate: an attachment was removed — ${why}]`;
            continue;
          }
          if (typeof part.text === "string" && !part.synthetic) {
            const mention = promptScopeViolation(cfg.scopes, part.text, cwd);
            if (mention) throw new Error(mention);
          }
        }
      }
      if (isOff(sessionID)) return;
      // An attached sensitive file (an @mention) is replaced by a note; test
      // fixtures are exempt, as for the read tool.
      for (const part of parts) {
        const path = part && typeof part === "object" && part.type === "file" ? attachedPath(part) : undefined;
        if (path && sensitivePathMatch(path, cfg.allowlist, cwd)) {
          for (const key of ["url", "filename", "mime", "source"] as const) delete part[key];
          part.type = "text";
          part.text = `[secretgate: an attachment was removed — '${path}' looks sensitive; reference its values as env vars instead]`;
        }
      }
      // [allow-secret] exempts only what the user typed — never attached file
      // content, which could otherwise carry the tag itself.
      const typed = (p: PromptPart): boolean => typeof p?.text === "string" && !p.synthetic && (p.type === undefined || p.type === "text");
      const bypass = parts.some((p) => typed(p) && String(p.text).includes(ALLOW_TAG));
      try {
        const vault = new Vault();
        const redact = eventRedactor(vault, "opencode:prompt", cfg.allowlist);
        const mapped = parts.map((part) => (typeof part?.text === "string" && !(bypass && typed(part)) ? redact(part.text) : undefined));
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
      const cfg = configFor(input?.sessionID);
      // Disabled: skip the secret checks, but keep the scope and keep restoring
      // placeholders so a disabled run never writes a dead SECRETGATE_ token.
      const decision = preToolPolicy(extractToolCall(tool, args), cfg, cwd, { disabled: isOff(input?.sessionID) });
      if (decision) {
        throw new Error(
          decision.action === "ask"
            ? `${decision.reason} OpenCode plugins cannot ask for approval, so this was refused: run it yourself if you meant it.`
            : decision.reason,
        );
      }
      const restoreThis = RESTORE_TOOLS.has(tool) || (tool === "bash" && cfg.restoreBash);
      if (restoreThis) {
        const vault = new Vault();
        mutateStringsInPlace(args, (s) => restorePlaceholders(s, vault).text);
      }
    },

    "tool.execute.after": async (
      input: { tool?: string; sessionID?: unknown; args?: unknown },
      output: { title?: string; output?: string; metadata?: unknown; content?: unknown; structuredContent?: unknown; attachments?: unknown; isError?: boolean },
    ) => {
      const tool = String(input?.tool ?? "").toLowerCase();
      try {
        const cfg = configFor(input?.sessionID);
        // glob/grep/list over a partly in-scope tree: drop out-of-scope entries.
        const kind = extractToolCall(tool, input?.args).kind;
        if (cfg.scopes.length > 0 && (kind === "search" || kind === "list") && typeof output?.output === "string") {
          output.output = filterSearchOutput(cfg.scopes, output.output, cwd).value as string;
        }
        if (isOff(input?.sessionID)) return;
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
