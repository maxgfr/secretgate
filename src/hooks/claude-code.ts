import { loadConfig } from "../config.js";
import { type DisableState, describeDisable, disableState, recordSession } from "../disable.js";
import { commandTouchesSensitivePath, sensitivePathMatch } from "../paths.js";
import { redactText } from "../redact.js";
import { restorePlaceholders } from "../redact.js";
import { Vault } from "../vault/vault.js";
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

// Fail CLOSED on every event. If secretgate crashes or the payload is too big to
// scan (a non-JSON sentinel from cmdHook), we never let unscanned content reach
// the model: a prompt is blocked, a tool call is denied, and — critically — a
// tool RESULT is WITHHELD (replaced with a notice via updatedToolOutput) rather
// than passed through raw. The old "fail open on post" was the one path by which
// an unscanned secret (e.g. a >20 MB log) could still reach the model.
function withholdOutput(reason: string): HookResult {
  return {
    stdout: JSON.stringify({
      systemMessage: `secretgate: ${reason} — tool output withheld`,
      hookSpecificOutput: { hookEventName: "PostToolUse", updatedToolOutput: `[secretgate withheld this tool output: ${reason}]` },
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

export async function handleClaudeCode(event: string, rawStdin: string, opts: { notices?: boolean } = {}): Promise<HookResult> {
  // Resolved BEFORE the guarded block on purpose. When the user has explicitly
  // switched secretgate off for this run, an unparseable payload must not fail
  // CLOSED — that would block the very session they told us to stay out of.
  const parsed = parseOrUndefined(rawStdin);
  if (event === "user-prompt-submit") recordSession(str(parsed?.session_id), str(parsed?.cwd));
  const state = disableState({ cwd: str(parsed?.cwd), sessionId: str(parsed?.session_id) });
  if (state.disabled) return disabledResult(event, parsed, state, opts.notices !== false);

  try {
    // Re-parse only on the failure path, so the thrown message (and the
    // fail-closed reason the user sees) stays the real parser error.
    const input = parsed ?? (JSON.parse(rawStdin) as Record<string, any>);
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
  } catch (err) {
    const detail = err instanceof Error ? err.message.slice(0, 200) : "unknown";
    const reason = `secretgate could not scan this safely (${detail}), failing closed`;
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
    return withholdOutput(reason);
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

  // 1) Sensitive-path deny (reads only — writing INTO .env is the restore flow).
  if (READ_TOOLS.has(toolName)) {
    const target = typeof toolInput.file_path === "string" ? toolInput.file_path : typeof toolInput.path === "string" ? toolInput.path : undefined;
    const hit = target ? sensitivePathMatch(target) : undefined;
    if (hit) {
      return deny(
        `secretgate: '${target}' looks sensitive (${hit}); its content must not enter the model. If the agent needs a value from it, reference it as an env var instead — or allow the file with \`secretgate allow --path '${target}'\`.`,
      );
    }
  }
  if (toolName === "Bash" && typeof toolInput.command === "string") {
    const touched = commandTouchesSensitivePath(toolInput.command);
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
      hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "allow", updatedInput: value },
    }),
    exit: 0,
  };
}

function postToolUse(input: Record<string, any>): HookResult {
  if (!("tool_response" in input)) return PASS;
  const toolName = String(input.tool_name ?? "");
  const cfg = loadConfig(typeof input.cwd === "string" ? input.cwd : undefined);
  const vault = new Vault();
  let redactions = 0;
  const { value, changed } = mapStrings(input.tool_response, (s) => {
    const r = redactText(s, vault, `claude-code:${toolName}`, { allowlist: cfg.allowlist, deadlineMs: SCAN_DEADLINE_MS });
    redactions += r.replaced.length;
    return r.text;
  });
  if (!changed) return PASS;
  return {
    stdout: JSON.stringify({
      systemMessage: `secretgate: redacted ${redactions} secret(s) from ${toolName} output`,
      hookSpecificOutput: { hookEventName: "PostToolUse", updatedToolOutput: value },
    }),
    exit: 0,
  };
}
