import { fileURLToPath } from "node:url";
import { loadConfig, type SecretgateConfig } from "../config.js";
import type { UserAllowlist } from "../engine/allowlist.js";
import { disableState, recordSession } from "../disable.js";
import { preToolPolicy } from "../hooks/policy.js";
import { eventRedactor, isBinaryField } from "../hooks/scan-budget.js";
import { extractToolCall } from "../hooks/tool-call.js";
import { applyPromptDirective, promptDirective } from "../prompt-directive.js";
import { sensitivePathMatch } from "../paths.js";
import { restorePlaceholders } from "../redact.js";
import { accessViolation, filterSearchOutput, promptScopeViolation, searchTextCounts } from "../scope.js";
import { Vault } from "../vault/vault.js";

// OpenCode plugin — bundled standalone as scripts/secretgate-opencode.mjs and
// installed into <config>/plugin/secretgate.js (<config> = $OPENCODE_CONFIG_DIR,
// else ~/.config/opencode). OpenCode's hook
// contract honors IN-PLACE mutations of the objects it passes (verified in
// opencode's session/tools.ts): mutate `parts[i].text`, `output.args.<prop>`
// and `output.output` — never reassign whole objects. Unlike Claude Code,
// OpenCode lets us REWRITE the prompt, so secrets in prompts are redacted
// (not blocked) here.
//
// IMPORTANT: this module must export ONLY the default plugin definition.
// OpenCode 2 runs `default.setup` (hook registrations via the plugin context);
// OpenCode 1 (>= 1.18.29) runs `default.server` (the legacy hook map). No
// other exports — plugin loaders treat extra exports as plugins.

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
//
// OpenCode 1 passes `{ directory, client }`; OpenCode 2 exposes the same facts
// on the plugin context (`ctx.location.directory`, `ctx.session`), which
// `v1ContextView` below translates before handing it here.
function projectState(ctx: unknown) {
  const directory = (ctx as { directory?: unknown } | undefined)?.directory;
  const cwd = typeof directory === "string" ? directory : process.cwd();
  const isOff = (sessionId?: unknown): boolean => disableState({ cwd, sessionId: typeof sessionId === "string" ? sessionId : undefined }).disabled;
  // One read of the pause and of the project config per event; `disable
  // --scope` lifts the scope too.
  const stateFor = (sessionId?: unknown): { off: boolean; cfg: SecretgateConfig } => {
    const state = disableState({ cwd, sessionId: typeof sessionId === "string" ? sessionId : undefined });
    const cfg = loadConfig(cwd);
    return { off: state.disabled, cfg: state.includesScope ? { ...cfg, scopes: [], error: undefined } : cfg };
  };
  return { cwd, isOff, stateFor };
}

/** Text the user typed: not an attachment, not a synthetic part. */
const typedText = (p: PromptPart | undefined): boolean => typeof p?.text === "string" && !p.synthetic && (p.type === undefined || p.type === "text");

const TEXT_MIME = /^(?:text\/|application\/(?:json|xml|javascript|x-yaml|yaml|toml|x-sh|x-www-form-urlencoded)\b|$)/;

// A text data URL (an @-attached file, inlined by OpenCode 2) is decoded,
// redacted and encoded back the same way; anything else is redacted as is.
function redactUri(uri: string, redact: (s: string) => string): string {
  const m = /^data:([^,;]*)((?:;[^,;]*)*),([\s\S]*)$/.exec(uri);
  if (!m) return redact(uri);
  const [, mime, params, payload] = m;
  if (!TEXT_MIME.test(mime!.toLowerCase())) return uri;
  const base64 = /;base64$/i.test(params!);
  let text: string;
  try {
    text = base64 ? Buffer.from(payload!, "base64").toString("utf8") : decodeURIComponent(payload!);
  } catch {
    return redact(uri);
  }
  const redacted = redact(text);
  if (redacted === text) return uri;
  return `data:${mime}${params},${base64 ? Buffer.from(redacted, "utf8").toString("base64") : encodeURIComponent(redacted)}`;
}

// Every context call hands back the whole history, so each string would be
// scanned again on every turn — quadratic in the session, and past the scan
// budget for a long one. Results are remembered by content (bounded), and
// forgotten when the allowlist changes.
const REMEMBER_CHARS = 32 * 1024 * 1024;
function redactionMemo() {
  let key = "";
  let size = 0;
  const seen = new Map<string, string>();
  return (allowlist: UserAllowlist, redact: (s: string) => string): ((s: string) => string) => {
    const k = JSON.stringify(allowlist);
    if (k !== key) {
      key = k;
      seen.clear();
      size = 0;
    }
    return (s) => {
      const known = seen.get(s);
      if (known !== undefined) return known;
      const out = s.startsWith("data:") ? redactUri(s, redact) : redact(s);
      if (size + s.length > REMEMBER_CHARS) {
        seen.clear();
        size = 0;
      }
      seen.set(s, out);
      size += s.length;
      return out;
    };
  };
}

const WITHHELD = "[secretgate withheld this tool output: scan failed or output exceeded the scan budget]";

async function buildHooks(ctx: unknown, state: ReturnType<typeof projectState> = projectState(ctx)) {
  const { cwd, isOff, stateFor } = state;
  const remembered = redactionMemo();
  // Typed text a prompt sent with [allow-secret]: the history must not redact
  // it afterwards (OpenCode 2 replays user text through the context hook).
  const bypassed = new Set<string>();
  const client = (ctx as { client?: { session?: { get?: (req: { path: { id: string } }) => Promise<{ data?: { parentID?: unknown } }> } } } | undefined)
    ?.client;
  // Whether a session is a subagent's: "unknown" when there is no session API
  // or the lookup fails. The off switch treats "unknown" as a subsession (it
  // fails SAFE: the user falls back to `secretgate disable` in a terminal).
  // (Without a session id nothing can be paused anyway.)
  const sessionKind = async (sessionId: unknown): Promise<"root" | "sub" | "unknown"> => {
    if (typeof sessionId !== "string") return "root";
    if (typeof client?.session?.get !== "function") return "unknown";
    try {
      const res = await client.session.get({ path: { id: sessionId } });
      return typeof res?.data?.parentID === "string" && res.data.parentID.length > 0 ? "sub" : "root";
    } catch {
      return "unknown";
    }
  };
  return {
    // OpenCode keeps rewritten args in tool history, including failed calls.
    // Redact that history immediately before it is converted to model messages.
    "experimental.chat.messages.transform": async (_input: unknown, output: { messages?: Array<{ info?: { sessionID?: string }; parts?: unknown[] }> }) => {
      // One pause check per session, one config, vault and budget per call.
      const off = new Map<string | undefined, boolean>();
      let redact: ((s: string) => string) | undefined;
      for (const message of output.messages ?? []) {
        const sessionID = message.info?.sessionID;
        if (!off.has(sessionID)) off.set(sessionID, isOff(sessionID));
        if (off.get(sessionID)) continue;
        try {
          for (const part of message.parts ?? []) {
            // V1 user text has already passed chat.message (including explicit
            // bypass); OpenCode 2 hands user content here as "user-content".
            const type = (part as { type?: string })?.type;
            if (type !== "tool" && type !== "user-content") continue;
            if (type === "user-content" && bypassed.has(String((part as { state?: { text?: unknown } }).state?.text))) continue;
            if (!redact) {
              const { allowlist } = loadConfig(cwd);
              redact = remembered(allowlist, eventRedactor(new Vault(), "opencode:history", allowlist));
            }
            mutateStringsInPlace(part, redact);
          }
        } catch {
          throw new Error("secretgate: tool history could not be scanned safely; start a fresh session.");
        }
      }
    },
    "chat.message": async (input: { sessionID?: unknown } | undefined, output: { message?: unknown; parts?: PromptPart[] }) => {
      const sessionID = input?.sessionID;
      const parts = output?.parts;
      // A subagent's prompt is written by the model (TaskTool feeds it through
      // chat.message): it is neither the session `secretgate disable` should
      // find, nor one allowed to switch secretgate off.
      const kind = await sessionKind(sessionID);
      if (kind !== "sub") recordSession(typeof sessionID === "string" ? sessionID : undefined, cwd);
      if (!Array.isArray(parts)) return;
      // `/secretgate off` typed by the user pauses this session. OpenCode
      // has no user-facing hook message, so the confirmation rides along in
      // the prompt for the model to relay.
      const said = parts.find((p) => typedText(p) && promptDirective(String(p.text)));
      if (said && kind !== "root") {
        said.text = `${said.text}\n\n[secretgate: ignored an off-switch — this session could not be confirmed as your main session (a subagent prompt is written by the model). Run \`secretgate disable --session\` in a terminal instead]`;
      } else if (said) {
        const notice = applyPromptDirective(promptDirective(String(said.text))!, typeof sessionID === "string" ? sessionID : undefined, cwd);
        said.text = `${said.text}\n\n[${notice}]`;
      }
      const { off, cfg } = stateFor(sessionID);
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
      if (off) return;
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
      const bypass = parts.some((p) => typedText(p) && String(p.text).includes(ALLOW_TAG));
      if (bypass) {
        for (const p of parts) if (typedText(p)) bypassed.add(String(p.text));
        if (bypassed.size > 64) bypassed.delete(bypassed.values().next().value!);
      }
      try {
        const vault = new Vault();
        const redact = eventRedactor(vault, "opencode:prompt", cfg.allowlist);
        const mapped = parts.map((part) => (typeof part?.text === "string" && !(bypass && typedText(part)) ? redact(part.text) : undefined));
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
      const { off, cfg } = stateFor(input?.sessionID);
      // Disabled: skip the secret checks, but keep the scope and keep restoring
      // placeholders so a disabled run never writes a dead SECRETGATE_ token.
      const decision = preToolPolicy(extractToolCall(tool, args), cfg, cwd, { disabled: off });
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
        const { off, cfg } = stateFor(input?.sessionID);
        // glob/grep/list over a partly in-scope tree: drop out-of-scope entries.
        const kind = extractToolCall(tool, input?.args).kind;
        if (cfg.scopes.length > 0 && (kind === "search" || kind === "list") && typeof output?.output === "string") {
          const filtered = filterSearchOutput(cfg.scopes, output.output, cwd);
          output.output = filtered.value as string;
          if (filtered.changed && kind === "search") {
            const counts = searchTextCounts(output.output, cwd);
            restateMetadataCounts(output.metadata, counts.matches, counts.files);
          }
        }
        if (off) return;
        const vault = new Vault();
        mutateStringsInPlace(output, eventRedactor(vault, `opencode:${tool}`, cfg.allowlist));
      } catch {
        const notice = WITHHELD;
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
}

// Shapes of the OpenCode 2 plugin context this adapter relies on. Kept
// structural (no @opencode/plugin dependency): the bundle is standalone.
interface V2Context {
  location?: { directory?: unknown };
  session: {
    hook(name: "context" | "prompt", callback: (event: any) => unknown): Promise<unknown>;
    get(input: { sessionID: string }): Promise<unknown>;
  };
  tool: {
    hook(name: "execute.before" | "execute.after", callback: (event: any) => unknown): Promise<unknown>;
  };
}

// OpenCode 1 passed a dedicated client object; OpenCode 2 mounts the domains
// on the plugin context itself. Present the V2 context in the V1 shape so the
// hook implementations above stay host-version agnostic.
function v1ContextView(ctx: V2Context): unknown {
  return {
    directory: ctx?.location?.directory,
    client: {
      session: {
        get: async ({ path }: { path: { id: string } }) => ({ data: await ctx.session.get({ sessionID: path.id }) }),
      },
    },
  };
}

// Search metadata (grep `{matches}`, glob `{count}`) still giving the
// pre-filter total would reveal that out-of-scope matches exist.
function restateMetadataCounts(metadata: unknown, matches: number, files: number): void {
  if (!metadata || typeof metadata !== "object") return;
  const m = metadata as Record<string, unknown>;
  if (typeof m.matches === "number") m.matches = matches;
  if (typeof m.count === "number") m.count = files;
}

// An OpenCode 2 search/list result: the model reads the text parts of
// `content`; `output` is the structured entry list (grep `{entry: {path}}`,
// one per match; glob `{path}`; relative to the project).
function filterListingResult(scopes: SecretgateConfig["scopes"], result: Record<string, any>, cwd: string, search: boolean): void {
  for (const part of Array.isArray(result.content) ? result.content : []) {
    if (part?.type === "text" && typeof part.text === "string") part.text = filterSearchOutput(scopes, part.text, cwd).value as string;
  }
  if (!Array.isArray(result.output)) return;
  const before = result.output.length;
  result.output = result.output.filter((item: any) => {
    const entry = item?.entry ?? item;
    if (typeof entry?.path !== "string") return true;
    const kind = entry.type === "directory" ? "list" : "read";
    return !scopes.some((s) => accessViolation(s, entry.path, cwd, kind));
  });
  if (search && result.output.length < before) restateMetadataCounts(result.metadata, result.output.length, result.output.length);
}

const SecretgatePlugin = {
  id: "secretgate",
  // OpenCode 1: return the legacy hook map.
  async server(ctx: unknown) {
    return buildHooks(ctx);
  },
  // OpenCode 2: register hooks on the domains that own the operation. Each
  // registration adapts the V2 event into the (input, output) call the shared
  // implementation expects, except tool results (see execute.after).
  async setup(ctx: V2Context) {
    const view = v1ContextView(ctx);
    const state = projectState(view);
    const hooks = await buildHooks(view, state);
    const { cwd, stateFor } = state;

    // The context messages are AI-SDK shaped: no per-message info, and tool
    // history lives in `tool-call` / `tool-result` content parts. Present each
    // message the way the transform implementation sees it, the real parts
    // wrapped so the redaction mutates them in place. A user message carries
    // the files @-attached to it (as text, or as a text data URL): those never
    // went through the prompt hook, which only saw their names.
    await ctx.session.hook("context", async (event) => {
      const messages: Array<{ role?: unknown; content?: unknown }> = Array.isArray(event?.messages) ? event.messages : [];
      await hooks["experimental.chat.messages.transform"](
        {},
        {
          messages: messages.map((message) => ({
            info: { sessionID: event?.sessionID },
            parts: (Array.isArray(message?.content) ? message.content : []).flatMap((part) => {
              if (part?.type === "tool-call" || part?.type === "tool-result") return [{ type: "tool", state: part }];
              if (message?.role === "user" && (part?.type === "text" || part?.type === "file")) return [{ type: "user-content", state: part }];
              return [];
            }),
          })),
        },
      );
    });

    await ctx.session.hook("prompt", async (event) => {
      const prompt = event && typeof event === "object" ? (event.prompt ?? {}) : {};
      const files: Array<Record<string, unknown>> = Array.isArray(prompt.files) ? prompt.files : [];
      const original = typeof prompt.text === "string" ? prompt.text : "";
      // Present the draft the way the chat.message implementation sees it: the
      // typed text first, then one part per attachment.
      const parts: PromptPart[] = [{ type: "text", text: original }];
      for (const file of files) {
        parts.push({ type: "file", url: file?.uri, filename: file?.filename, mime: file?.mime });
      }
      await hooks["chat.message"]({ sessionID: event?.sessionID }, { parts });
      // Attachments the implementation replaced with a note leave the draft;
      // their note rides the prompt text so the model sees what happened.
      const kept: Array<Record<string, unknown>> = [];
      const notes: string[] = [];
      for (let i = 0; i < files.length; i++) {
        const draft = files[i];
        if (!draft) continue;
        const part = parts[1 + i];
        if (part?.type === "file") kept.push(draft);
        else if (typeof part?.text === "string") notes.push(part.text);
      }
      let text = typeof parts[0]?.text === "string" ? (parts[0].text as string) : original;
      if (notes.length > 0) text = `${text}\n\n${notes.join("\n\n")}`;
      if (typeof prompt.text === "string") prompt.text = text;
      if (files.length > 0) prompt.files = kept;
      // Rewriting the text can shift @mention offsets — drop them rather than
      // leave an offset pointing at the wrong range.
      if (text !== original) {
        for (const file of kept) delete file.mention;
      }
    });

    await ctx.tool.hook("execute.before", async (event) => {
      // OpenCode 2 names its shell tool `shell`; the implementation knows it as
      // `bash` (same policy, and `restoreBash` applies to it).
      const tool = String(event?.tool ?? "").toLowerCase() === "shell" ? "bash" : event?.tool;
      await hooks["tool.execute.before"]({ tool, sessionID: event?.sessionID }, { args: event?.input ?? {} });
    });

    // The result shape differs from V1 — `content` text parts are what the
    // model reads, `output` is structured — so scope and withhold are adapted
    // here; redaction still reaches every nested string.
    await ctx.tool.hook("execute.after", async (event) => {
      // Failed executions carry no result to redact; the error path is untouched.
      if (event?.status !== "completed") return;
      const result = event.result;
      if (!result || typeof result !== "object") throw new Error(WITHHELD);
      const tool = String(event?.tool ?? "").toLowerCase();
      try {
        const { off, cfg } = stateFor(event?.sessionID);
        const kind = extractToolCall(tool, event?.input).kind;
        if (cfg.scopes.length > 0 && (kind === "search" || kind === "list")) filterListingResult(cfg.scopes, result, cwd, kind === "search");
        if (off) return;
        mutateStringsInPlace(result, eventRedactor(new Vault(), `opencode:${tool}`, cfg.allowlist));
      } catch {
        // Keep `output`'s type for consumers of the structured result.
        const output = result.output;
        for (const key of Object.keys(result)) delete result[key];
        result.content = [{ type: "text", text: WITHHELD }];
        result.output = Array.isArray(output) ? [] : output && typeof output === "object" ? {} : WITHHELD;
        result.metadata = {};
      }
    });
  },
};

export default SecretgatePlugin;
