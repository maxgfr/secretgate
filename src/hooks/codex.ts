import { DEFER, type HookResult, handleClaudeCode } from "./claude-code.js";

// Codex CLI speaks the same hook protocol family as Claude Code (stdin JSON,
// decision/hookSpecificOutput on stdout), so prompt blocking and tool-input
// handling are shared. PostToolUse is the exception: Codex parses
// output-rewrite fields but does NOT apply them yet ("updatedMCPToolOutput …
// not supported"), so the post event is a deliberate no-op — spending a scan
// there would only pretend to protect. Known upstream gaps (documented in the
// README): no output redaction, and hooks don't fire under `codex exec`.
export async function handleCodex(event: string, rawStdin: string): Promise<HookResult> {
  if (event === "post-tool-use") return { stdout: "", exit: 0 };
  const r = await handleClaudeCode(event, rawStdin);
  // The "{}" abstain is a Claude-Code-only workaround (claude-code#77782);
  // Codex keeps its silent empty-stdout abstain.
  return r === DEFER ? { stdout: "", exit: 0 } : r;
}
