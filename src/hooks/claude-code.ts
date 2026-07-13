import { loadConfig } from "../config.js";
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

// Every handler is wrapped fail-closed for PRE events: if secretgate itself
// crashes on malformed input, the prompt/tool call is blocked rather than
// silently let through. POST events fail open — the tool already ran and we
// cannot invent the redacted output we failed to compute.
export async function handleClaudeCode(event: string, rawStdin: string): Promise<HookResult> {
  try {
    const input = JSON.parse(rawStdin) as Record<string, any>;
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
    const reason = `secretgate internal error — failing closed (${err instanceof Error ? err.message.slice(0, 200) : "unknown"})`;
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
    return PASS;
  }
}

function userPromptSubmit(input: Record<string, any>): HookResult {
  const prompt = String(input.prompt ?? "");
  if (prompt.includes(ALLOW_TAG)) return PASS;
  const cfg = loadConfig(typeof input.cwd === "string" ? input.cwd : undefined);
  const vault = new Vault();
  const r = redactText(prompt, vault, "claude-code:prompt", { allowlist: cfg.allowlist });
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
  const cfg = loadConfig(typeof input.cwd === "string" ? input.cwd : undefined);

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
  const restoreThis = RESTORE_TOOLS.has(toolName) || (toolName === "Bash" && cfg.restoreBash);
  if (restoreThis) {
    const vault = new Vault();
    const { value, changed } = mapStrings(toolInput, (s) => restorePlaceholders(s, vault).text);
    if (changed) {
      return {
        stdout: JSON.stringify({
          hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "allow", updatedInput: value },
        }),
        exit: 0,
      };
    }
  }
  return PASS;
}

function postToolUse(input: Record<string, any>): HookResult {
  if (!("tool_response" in input)) return PASS;
  const toolName = String(input.tool_name ?? "");
  const cfg = loadConfig(typeof input.cwd === "string" ? input.cwd : undefined);
  const vault = new Vault();
  let redactions = 0;
  const { value, changed } = mapStrings(input.tool_response, (s) => {
    const r = redactText(s, vault, `claude-code:${toolName}`, { allowlist: cfg.allowlist });
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
