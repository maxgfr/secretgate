import { loadConfig, type SecretgateConfig } from "../config.js";
import { type DisableState, describeDisable, disableState, recordSession } from "../disable.js";
import { applyPromptDirective, promptDirective } from "../prompt-directive.js";
import { redactText } from "../redact.js";
import { restorePlaceholders } from "../redact.js";
import { sensitivePathMatch } from "../paths.js";
import { filterSearchOutput, promptMentions, promptScopeViolation } from "../scope.js";
import { Vault } from "../vault/vault.js";
import { preToolPolicy } from "./policy.js";
import { eventRedactor, isBinaryField, SCAN_CAP } from "./scan-budget.js";
import { isStoppedSession, stopSession } from "./stopped-session.js";
import { extractToolCall } from "./tool-call.js";
import { mapStrings } from "./walk.js";

export interface HookResult {
  stdout: string;
  exit: number;
}

const ALLOW_TAG = "[allow-secret]";
const PASS: HookResult = { stdout: "", exit: 0 };
// claude-code#77782: a PreToolUse hook that abstains with EMPTY stdout is misread
// as plain text and forces an interactive permission prompt on every matched tool
// call — breaking auto mode and ignoring allow rules. "{}" (valid JSON, no
// decision) is the abstain that works everywhere; the documented "defer" decision
// value is rejected by Claude Code <= 2.1.212.
export const DEFER: HookResult = { stdout: "{}", exit: 0 };
// Wall-clock budget per hook scan. Well under a typical agent hook timeout so a
// crafted payload can't stall the hook into a fail-open timeout; on exceed the
// scan throws and we fail closed.
const SCAN_DEADLINE_MS = 5000;

// Handle scan failures using each host's contract: block prompts, deny calls,
// replace supported output envelopes, or stop when no safe rewrite is known.
// Host timeouts and transports outside these hooks remain outside this guard.
function withholdOutput(reason: string, input?: Record<string, any>, blockFallback = false): HookResult {
  const notice = `[secretgate withheld this tool output: ${reason}]`;
  const tool = String(input?.tool_name ?? "");
  let replacement: unknown;
  if (tool === "Bash") {
    replacement = { stdout: notice, stderr: "", interrupted: false, isImage: false };
  } else if (tool === "Read" && input?.tool_response?.type === "text" && typeof input.tool_response.file?.filePath === "string") {
    replacement = { type: "text", file: { filePath: input.tool_response.file.filePath, content: notice, numLines: 1, startLine: 1, totalLines: 1 } };
  } else if (tool.startsWith("mcp__")) {
    replacement = Array.isArray(input?.tool_response) ? [{ type: "text", text: notice }] : { content: [{ type: "text", text: notice }], isError: true };
  }
  if (replacement === undefined && blockFallback) replacement = notice;
  // Unknown/malformed envelopes cannot safely be replaced with a string:
  // Claude silently ignores schema-invalid replacements. Stop this turn.
  if (replacement === undefined) {
    try {
      stopSession(input?.session_id);
    } catch {
      // Unwritable state dir: still stop THIS turn. Throwing here would crash
      // the hook with empty stdout, which the host treats as a pass.
    }
    return {
      stdout: JSON.stringify({
        continue: false,
        stopReason: `secretgate: ${reason}. Processing stopped; start a fresh session before retrying with smaller output.`,
      }),
      exit: 0,
    };
  }
  return {
    stdout: JSON.stringify({
      systemMessage: `secretgate: ${reason} — tool output withheld`,
      hookSpecificOutput: { hookEventName: "PostToolUse", updatedToolOutput: replacement },
    }),
    exit: 0,
  };
}

// Best-effort parse used to resolve the disable state before the guarded block.
function parseOrUndefined(raw: string): Record<string, any> | undefined {
  try {
    const v = JSON.parse(raw);
    return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, any>) : undefined;
  } catch {
    return undefined;
  }
}

const str = (v: unknown): string | undefined => (typeof v === "string" && v.length > 0 ? v : undefined);

/** The fail-closed answer for an event, when the hook itself cannot decide. */
export function failClosed(event: string, input?: Record<string, any>, blockFallback = false): HookResult {
  const reason = "secretgate could not scan this safely (invalid input, scan budget or local storage error)";
  if (event === "user-prompt-submit") return { stdout: JSON.stringify({ decision: "block", reason }), exit: 0 };
  if (event === "pre-tool-use") return deny(reason);
  return withholdOutput(reason, input, blockFallback);
}

// What each event does while secretgate is off. Restore keeps running (a
// disabled run must never leave dead SECRETGATE_ placeholders behind in files
// the agent writes), and so does the project scope: a pause switches off
// secret scanning, not the boundary the repository declared.
function disabledResult(event: string, input: Record<string, any> | undefined, state: DisableState, notices: boolean): HookResult {
  // `disable --scope` lifts the project scope as well.
  const load = (cwd: string | undefined): SecretgateConfig => {
    const cfg = loadConfig(cwd);
    return state.includesScope ? { ...cfg, scopes: [], error: undefined } : cfg;
  };
  if (event === "pre-tool-use") {
    if (input === undefined) return DEFER;
    const cfg = load(str(input.cwd));
    const decision = preToolPolicy(extractToolCall(String(input.tool_name ?? ""), input.tool_input), cfg, str(input.cwd) ?? process.cwd(), { disabled: true });
    if (decision) return deny(decision.reason);
    try {
      return restoreOnly(input, cfg);
    } catch {
      // A disabled hook must never crash the tool call it is not policing.
      return DEFER;
    }
  }
  if (event === "user-prompt-submit") {
    const cfg = input ? load(str(input.cwd)) : undefined;
    const outOfScope = cfg && input ? promptScopeViolation(cfg.scopes, String(input.prompt ?? ""), str(input.cwd) ?? process.cwd()) : undefined;
    if (outOfScope) return { stdout: JSON.stringify({ decision: "block", reason: outOfScope }), exit: 0 };
    if (!notices) return PASS;
    // Announced on every prompt, not on every tool call: once per turn is loud
    // enough to be impossible to forget, quiet enough to stay usable.
    return {
      stdout: JSON.stringify({
        systemMessage: `secretgate is DISABLED — ${describeDisable(state)}. Prompts, tool input and tool output are NOT being scanned. Re-enable with \`secretgate enable\`.`,
      }),
      exit: 0,
    };
  }
  if (event === "post-tool-use") {
    if (input === undefined || !("tool_response" in input)) return PASS;
    const cfg = load(str(input.cwd));
    const filtered = scopeFilter(input, cfg);
    return filtered.changed ? updatedOutput(filtered.value) : PASS;
  }
  return { stdout: "", exit: 2 };
}

export async function handleClaudeCode(event: string, rawStdin: string, opts: { notices?: boolean; blockFallback?: boolean } = {}): Promise<HookResult> {
  // Parse best-effort so explicit pauses also apply to malformed events.
  const parsed = parseOrUndefined(rawStdin);
  try {
    // "désactive secretgate" typed by the user pauses this session, and it
    // takes effect for this very prompt.
    let notice: string | undefined;
    if (event === "user-prompt-submit") {
      recordSession(str(parsed?.session_id), str(parsed?.cwd));
      const directive = typeof parsed?.prompt === "string" ? promptDirective(parsed.prompt) : undefined;
      if (directive) notice = applyPromptDirective(directive, str(parsed?.session_id), str(parsed?.cwd));
    }
    const withNotice = (r: HookResult): HookResult => (notice && opts.notices !== false ? addSystemMessage(r, notice) : r);
    const state = disableState({ cwd: str(parsed?.cwd), sessionId: str(parsed?.session_id) });
    if (state.disabled) return withNotice(disabledResult(event, parsed, state, opts.notices !== false && !notice));
    if (notice) return withNotice(handleEnabled(event, rawStdin, parsed, opts));
    return handleEnabled(event, rawStdin, parsed, opts);
  } catch {
    // Parser/vault error messages can contain raw input. Never echo them.
    return failClosed(event, parsed, opts.blockFallback);
  }
}

// Show `message` to the user alongside whatever the hook decided.
function addSystemMessage(r: HookResult, message: string): HookResult {
  const out = r.stdout.trim() ? (JSON.parse(r.stdout) as Record<string, unknown>) : {};
  out.systemMessage = typeof out.systemMessage === "string" ? `${message}\n${out.systemMessage}` : message;
  return { stdout: JSON.stringify(out), exit: r.exit };
}

function handleEnabled(event: string, rawStdin: string, parsed: Record<string, any> | undefined, opts: { blockFallback?: boolean }): HookResult {
  if (!opts.blockFallback && isStoppedSession(parsed?.session_id)) {
    const reason = "secretgate stopped this session after an unscannable tool result. Start a fresh session; resuming may expose the old result.";
    if (event === "user-prompt-submit") return { stdout: JSON.stringify({ decision: "block", reason }), exit: 0 };
    if (event === "pre-tool-use") return deny(reason);
    return { stdout: JSON.stringify({ continue: false, stopReason: reason }), exit: 0 };
  }
  // Re-parse only on the failure path; the catch never exposes parser text.
  const input = parsed ?? (JSON.parse(rawStdin) as Record<string, any>);
  if (input === null || typeof input !== "object") throw new Error("event is not an object");
  if ((event !== "post-tool-use" && rawStdin.length > SCAN_CAP) || input.__secretgate_unscannable) throw new Error("input exceeds scan budget");
  // One config read per event (it walks up to the project root).
  const cfg = loadConfig(str(input.cwd));
  switch (event) {
    case "user-prompt-submit":
      return userPromptSubmit(input, cfg);
    case "pre-tool-use":
      return preToolUse(input, cfg);
    case "post-tool-use":
      return postToolUse(input, cfg);
    default:
      return { stdout: "", exit: 2 };
  }
}

function userPromptSubmit(input: Record<string, any>, cfg: SecretgateConfig): HookResult {
  const prompt = String(input.prompt ?? "");
  // @file mentions inline file content without firing a tool hook.
  const cwd = str(input.cwd) ?? process.cwd();
  const outOfScope = promptScopeViolation(cfg.scopes, prompt, cwd);
  if (outOfScope) return { stdout: JSON.stringify({ decision: "block", reason: outOfScope }), exit: 0 };
  if (prompt.includes(ALLOW_TAG)) return PASS;
  // The host inlines an @-mentioned file with no tool call to deny: check the
  // mention itself (test fixtures are exempt, as for Read).
  const sensitive = promptMentions(prompt, cwd).find((m) => sensitivePathMatch(m.abs, cfg.allowlist, cwd));
  if (sensitive) {
    const reason = `secretgate blocked this prompt: @${sensitive.raw} looks sensitive, and mentioning it would send its content to the model. Reference the values as env vars instead, allow the file with \`secretgate allow --path '${sensitive.raw}'\`, or add ${ALLOW_TAG} to send it anyway.`;
    return { stdout: JSON.stringify({ decision: "block", reason }), exit: 0 };
  }
  const vault = new Vault();
  const r = redactText(prompt, vault, "claude-code:prompt", { allowlist: cfg.allowlist, deadlineMs: SCAN_DEADLINE_MS });
  if (r.findings.length === 0) return PASS;
  const rules = [...new Set(r.findings.map((f) => f.ruleId))].join(", ");
  const reason = [
    `secretgate blocked this prompt: detected ${rules}.`,
    "",
    "A redacted copy you can resend (placeholders map to your real values locally and will be restored when written to files):",
    "",
    r.text,
    "",
    `To send the original anyway, add ${ALLOW_TAG} to your prompt. To permanently allow a value: \`secretgate allow <value>\`.`,
  ].join("\n");
  return { stdout: JSON.stringify({ decision: "block", reason }), exit: 0 };
}

function deny(reason: string): HookResult {
  return {
    stdout: JSON.stringify({
      hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: reason },
    }),
    exit: 0,
  };
}

function ask(reason: string): HookResult {
  return {
    stdout: JSON.stringify({
      hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "ask", permissionDecisionReason: reason },
    }),
    exit: 0,
  };
}

// Tool names vary across agents (Claude Code: Write/Edit…; Codex:
// apply_patch…). Only restore needs this; policies use extractToolCall.
function normalizeToolName(name: string): string {
  switch (name.toLowerCase()) {
    case "bash":
    case "shell":
    case "exec":
    case "exec_command":
    case "local_shell":
    case "localshell":
    case "run_command":
      return "Bash";
    case "write":
    case "write_file":
    case "create_file":
      return "Write";
    case "edit":
    case "multiedit":
    case "notebookedit":
    case "str_replace":
    case "str_replace_editor":
    case "edit_file":
    case "apply_patch":
    case "patch":
      return "Edit";
    default:
      return name;
  }
}

// Tools whose input may legitimately carry placeholders back to disk.
const RESTORE_TOOLS = new Set(["Write", "Edit"]);

function preToolUse(input: Record<string, any>, cfg: SecretgateConfig): HookResult {
  const cwd = str(input.cwd) ?? process.cwd();
  const decision = preToolPolicy(extractToolCall(String(input.tool_name ?? ""), input.tool_input), cfg, cwd, { disabled: false });
  if (decision?.action === "deny") return deny(decision.reason);
  if (decision?.action === "ask") return ask(decision.reason);
  return restoreOnly(input, cfg);
}

// Placeholder restore, in isolation. Split out because it runs on BOTH paths:
// with the firewall on it is the last step of preToolUse, and with the firewall
// off it still runs — otherwise a disabled run would write dead SECRETGATE_
// placeholders into the user's files.
function restoreOnly(input: Record<string, any>, cfg: SecretgateConfig): HookResult {
  const toolName = normalizeToolName(String(input.tool_name ?? ""));
  const toolInput = input.tool_input ?? {};
  if (!RESTORE_TOOLS.has(toolName) && !(toolName === "Bash" && cfg.restoreBash)) return DEFER;
  const vault = new Vault();
  const { value, changed } = mapStrings(toolInput, (s) => restorePlaceholders(s, vault).text);
  if (!changed) return DEFER;
  return {
    stdout: JSON.stringify({
      hookSpecificOutput: { hookEventName: "PreToolUse", updatedInput: value },
    }),
    exit: 0,
  };
}

// Glob/Grep/LS over a partly in-scope tree: drop the out-of-scope entries.
function scopeFilter(input: Record<string, any>, cfg: SecretgateConfig): { value: unknown; changed: boolean } {
  if (cfg.scopes.length === 0) return { value: input.tool_response, changed: false };
  const call = extractToolCall(String(input.tool_name ?? ""), input.tool_input);
  if (call.kind !== "search" && call.kind !== "list") return { value: input.tool_response, changed: false };
  return filterSearchOutput(cfg.scopes, input.tool_response, str(input.cwd) ?? process.cwd());
}

function updatedOutput(value: unknown): HookResult {
  return {
    stdout: JSON.stringify({
      hookSpecificOutput: { hookEventName: "PostToolUse", updatedToolOutput: value },
    }),
    exit: 0,
  };
}

function postToolUse(input: Record<string, any>, cfg: SecretgateConfig): HookResult {
  if (!("tool_response" in input)) return PASS;
  const toolName = String(input.tool_name ?? "");
  const filtered = scopeFilter(input, cfg);
  const vault = new Vault();
  const { value, changed } = mapStrings(filtered.value, eventRedactor(vault, `claude-code:${toolName}`, cfg.allowlist), isBinaryField);
  if (!changed && !filtered.changed) return PASS;
  return updatedOutput(value);
}
