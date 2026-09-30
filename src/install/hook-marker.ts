// Recognises secretgate's own hook entries in an agent's settings, whatever
// path the CLI is invoked by (`secretgate hook codex pre-tool-use`,
// `node "…/secretgate.mjs" hook codex pre-tool-use`). The event argument is
// part of the signature: another tool's `… hook codex` (scopelet, …) is not
// ours — counting it inflates `status`, and treating it as ours would let
// install/uninstall delete a hook secretgate never wrote.
const EVENT_ARGS = "(?:user-prompt-submit|pre-tool-use|post-tool-use)";

export function isSecretgateHook(command: unknown, agent: "claude-code" | "codex"): boolean {
  return typeof command === "string" && new RegExp(`(?:^|\\s)hook\\s+${agent}\\s+${EVENT_ARGS}(?:\\s|$)`).test(command);
}
