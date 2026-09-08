import { loadConfig } from "../config.js";
import { type DisableState, describeDisable, disableState, recordSession } from "../disable.js";
import { commandTouchesSensitivePath, sensitivePathMatch } from "../paths.js";
import { redactText } from "../redact.js";
import { restorePlaceholders } from "../redact.js";
import { Vault } from "../vault/vault.js";
import { mapStrings } from "./walk.js";
import { eventRedactor, isBinaryField, SCAN_CAP } from "./scan-budget.js";
import { isStoppedSession, stopSession } from "./stopped-session.js";

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
    stopSession(input?.session_id);
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
    return JSON.parse(raw) as Record<string, any>;
  } catch {
    return undefined;
  }
}

const str = (v: unknown): string | undefined => (typeof v === "string" && v.length > 0 ? v : undefined);

// What each event does while secretgate is off. Restore is the one thing that
// keeps running: a disabled run must never leave dead SECRETGATE_ placeholders
// behind in files the agent writes.
function disabledResult(event: string, input: Record<string, any> | undefined, state: DisableState, notices: boolean): HookResult {
  if (event === "pre-tool-use") {
    if (input === null || typeof input !== "object") return DEFER;
    try {
      return restoreOnly(input);
    } catch {
      // A disabled hook must never crash the tool call it is not policing.
      return DEFER;
    }
  }
  if (event === "user-prompt-submit") {
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
  if (event === "post-tool-use") return PASS;
  return { stdout: "", exit: 2 };
}

export async function handleClaudeCode(event: string, rawStdin: string, opts: { notices?: boolean; blockFallback?: boolean } = {}): Promise<HookResult> {
  // Parse best-effort so explicit pauses also apply to malformed events.
  const parsed = parseOrUndefined(rawStdin);
  try {
    if (event === "user-prompt-submit") recordSession(str(parsed?.session_id), str(parsed?.cwd));
    const state = disableState({ cwd: str(parsed?.cwd), sessionId: str(parsed?.session_id) });
    if (state.disabled) return disabledResult(event, parsed, state, opts.notices !== false);
    if (!opts.blockFallback && isStoppedSession(parsed?.session_id)) {
      const reason = "secretgate stopped this session after an unscannable tool result. Start a fresh session; resuming may expose the old result.";
      if (event === "user-prompt-submit") return { stdout: JSON.stringify({ decision: "block", reason }), exit: 0 };
      if (event === "pre-tool-use") return deny(reason);
      return { stdout: JSON.stringify({ continue: false, stopReason: reason }), exit: 0 };
    }
    // Re-parse only on the failure path; the catch never exposes parser text.
    const input = parsed ?? (JSON.parse(rawStdin) as Record<string, any>);
    if ((event !== "post-tool-use" && rawStdin.length > SCAN_CAP) || input.__secretgate_unscannable) throw new Error("input exceeds scan budget");
    switch (event) {
      case "user-prompt-submit":
        return userPromptSubmit(input);
      case "pre-tool-use":
        return preToolUse(input);
      case "post-tool-use":
        return postToolUse(input);
      default:
        return { stdout: "", exit: 2 };
    }
  } catch {
    // Parser/vault error messages can contain raw input. Never echo them.
    const reason = "secretgate could not scan this safely (invalid input, scan budget or local storage error)";
    if (event === "user-prompt-submit") {
      return { stdout: JSON.stringify({ decision: "block", reason }), exit: 0 };
    }
    if (event === "pre-tool-use") {
      return {
        stdout: JSON.stringify({
          hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: reason },
        }),
        exit: 0,
      };
    }
    return withholdOutput(reason, parsed, opts.blockFallback);
  }
}

function userPromptSubmit(input: Record<string, any>): HookResult {
  const prompt = String(input.prompt ?? "");
  if (prompt.includes(ALLOW_TAG)) return PASS;
  const cfg = loadConfig(typeof input.cwd === "string" ? input.cwd : undefined);
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

// Tool names vary across agents (Claude Code: Read/Write/Bash…; Codex:
// shell/apply_patch/read_file…). Normalize before classifying.
function normalizeToolName(name: string): string {
  switch (name.toLowerCase()) {
    case "bash":
    case "shell":
    case "exec":
    case "local_shell":
    case "localshell":
    case "run_command":
      return "Bash";
    case "read":
    case "read_file":
    case "view":
    case "open_file":
      return "Read";
    case "grep":
    case "search":
      return "Grep";
    case "write":
    case "write_file":
    case "create_file":
      return "Write";
    case "edit":
    case "multiedit":
    case "notebookedit":
    case "str_replace":
    case "apply_patch":
    case "patch":
      return "Edit";
    default:
      return name;
  }
}

// Tools whose input may legitimately carry placeholders back to disk.
const RESTORE_TOOLS = new Set(["Write", "Edit"]);
// Tools that read file content — denied on sensitive paths.
const READ_TOOLS = new Set(["Read", "Grep"]);

function preToolUse(input: Record<string, any>): HookResult {
  const toolName = normalizeToolName(String(input.tool_name ?? ""));
  const toolInput = (input.tool_input ?? {}) as Record<string, any>;
  const cfg = loadConfig(str(input.cwd));

  // 1) Sensitive-path deny (reads only — writing INTO .env is the restore flow).
  if (READ_TOOLS.has(toolName)) {
    const target = typeof toolInput.file_path === "string" ? toolInput.file_path : typeof toolInput.path === "string" ? toolInput.path : undefined;
    const hit = target ? sensitivePathMatch(target, cfg.allowlist, str(input.cwd)) : undefined;
    if (hit) {
      return deny(
        `secretgate: '${target}' looks sensitive (${hit}); its content must not enter the model. If the agent needs a value from it, reference it as an env var instead — or allow the file with \`secretgate allow --path '${target}'\`.`,
      );
    }
  }
  if (toolName === "Bash" && typeof toolInput.command === "string") {
    const touched = commandTouchesSensitivePath(toolInput.command, cfg.allowlist, str(input.cwd));
    if (touched) {
      return deny(`secretgate: this command touches '${touched}', which looks sensitive. Its content must not enter the model.`);
    }
  }

  // 2) Placeholder restore on the way back to disk.
  return restoreOnly(input);
}

// Placeholder restore, in isolation. Split out because it runs on BOTH paths:
// with the firewall on it is step 2 of preToolUse, and with the firewall off it
// is the only thing that still runs — otherwise a disabled run would write dead
// SECRETGATE_ placeholders into the user's files.
function restoreOnly(input: Record<string, any>): HookResult {
  const toolName = normalizeToolName(String(input.tool_name ?? ""));
  const toolInput = (input.tool_input ?? {}) as Record<string, any>;
  const cfg = loadConfig(str(input.cwd));
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

function postToolUse(input: Record<string, any>): HookResult {
  if (!("tool_response" in input)) return PASS;
  const toolName = String(input.tool_name ?? "");
  const cfg = loadConfig(typeof input.cwd === "string" ? input.cwd : undefined);
  const vault = new Vault();
  const { value, changed } = mapStrings(input.tool_response, eventRedactor(vault, `claude-code:${toolName}`, cfg.allowlist), isBinaryField);
  if (!changed) return PASS;
  return {
    stdout: JSON.stringify({
      hookSpecificOutput: { hookEventName: "PostToolUse", updatedToolOutput: value },
    }),
    exit: 0,
  };
}
