import { DEFER, type HookResult, handleClaudeCode } from "./claude-code.js";

// Codex CLI speaks the same hook protocol family as Claude Code (stdin JSON,
// decision/hookSpecificOutput on stdout), so prompt blocking and tool-input
// handling are shared. Codex does not apply PostToolUse output-rewrite fields,
// but a `decision: "block"` rejects the original result and replaces the
// model-visible result with `reason`. We therefore reuse the Claude scanner,
// then adapt its redacted updatedToolOutput into that block-and-replace shape.
export async function handleCodex(event: string, rawStdin: string): Promise<HookResult> {
  // `notices: false`: the "secretgate is DISABLED" banner is a bare
  // `systemMessage`, a Claude Code output field. Codex has no equivalent, so it
  // stays silent there rather than handing Codex JSON it has no field for.
  const r = await handleClaudeCode(event, rawStdin, { notices: false, blockFallback: true });
  if (event === "pre-tool-use" && r.stdout.trim()) {
    const output = JSON.parse(r.stdout);
    if (output.hookSpecificOutput?.updatedInput !== undefined) {
      // Codex requires allow with rewritten arguments; its own tool approvals
      // remain enforced separately. Claude supports decision-free updatedInput.
      output.hookSpecificOutput.permissionDecision = "allow";
      return { ...r, stdout: JSON.stringify(output) };
    }
  }
  if (event === "post-tool-use") {
    if (!r.stdout.trim()) return r;
    const output = JSON.parse(r.stdout) as { continue?: boolean; stopReason?: string; hookSpecificOutput?: { updatedToolOutput?: unknown } };
    const replacement =
      output.continue === false ? "[secretgate withheld this tool output: it could not be scanned safely]" : output.hookSpecificOutput?.updatedToolOutput;
    if (replacement === undefined) return { stdout: "", exit: r.exit };
    const text = typeof replacement === "string" ? replacement : JSON.stringify(replacement);
    return {
      stdout: JSON.stringify({
        decision: "block",
        reason: `secretgate replaced the original tool result with this locally redacted output:\n\n${text}`,
      }),
      exit: 0,
    };
  }
  // The "{}" abstain is a Claude-Code-only workaround (claude-code#77782);
  // Codex keeps its silent empty-stdout abstain.
  return r === DEFER ? { stdout: "", exit: 0 } : r;
}
