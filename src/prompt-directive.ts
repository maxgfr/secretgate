import { addPause, describeDisable, disableState, removePause } from "./disable.js";

// Turning secretgate off from the conversation: the user invokes the skill by
// name and THIS session is paused until it ends — no command for the agent to
// run, so the agent itself never needs the power to switch its own firewall
// off (an agent-run `secretgate disable` asks for approval instead, see
// hooks/policy.ts).
//
//   /secretgate off | disable | pause | stop     ($secretgate … in Codex)
//   /secretgate off scope | disable --scope      (also lifts the project scope)
//   /secretgate on | enable | resume
//
// Only prompts the user submits are read (UserPromptSubmit / the OpenCode prompt hook),
// never tool output, and only their FIRST non-empty line, which must be the
// directive and nothing else. A pasted log, a quoted block or a sentence about
// the feature never switches anything, and there is no natural-language form:
// prose is exactly what a model or a fetched page can write.

export type PromptDirective = { action: "disable"; liftScope: boolean } | { action: "enable" };

const SKILL_DISABLE = /^[/$]secretgate\s+(?:disable|off|pause|stop)(\s+(?:--)?scope)?\s*[.!]?$/i;
const SKILL_ENABLE = /^[/$]secretgate\s+(?:enable|on|resume)\s*[.!]?$/i;

export function promptDirective(prompt: string): PromptDirective | undefined {
  const first = prompt.split(/\r?\n/).find((l) => l.trim() !== "");
  if (first === undefined) return undefined;
  // `opencode run "/secretgate off"` delivers the message still quoted.
  const line = first
    .trim()
    .replace(/^(["'`])(.*)\1$/, "$2")
    .trim();
  const off = SKILL_DISABLE.exec(line);
  if (off) return { action: "disable", liftScope: Boolean(off[1]) };
  if (SKILL_ENABLE.test(line)) return { action: "enable" };
  return undefined;
}

/** Apply a directive for one session. Returns the message to show the user. */
export function applyPromptDirective(directive: PromptDirective, sessionId: string | undefined, cwd: string | undefined): string {
  if (!sessionId) {
    return "secretgate: this agent did not report a session id, so it cannot be paused from the conversation — run `secretgate disable --session` in a terminal instead.";
  }
  if (directive.action === "enable") {
    const cleared = removePause("session", sessionId);
    const still = disableState({ sessionId, cwd });
    if (still.disabled) {
      const how = still.scope === "env" ? "unset SECRETGATE_DISABLE and restart the agent" : "run `secretgate enable` in a terminal";
      return `secretgate: ${cleared.length > 0 ? "this session's pause is cleared, but " : ""}secretgate is still DISABLED here — ${describeDisable(still)}. That pause is not the session's own: ${how}.`;
    }
    return cleared.length > 0
      ? "secretgate: re-enabled for this session, at your request. Prompts, tool input and tool output are scanned again."
      : "secretgate: already active for this session.";
  }
  addPause({ scope: "session", target: sessionId, minutes: null, cwd, lifetime: true, liftScope: directive.liftScope });
  return [
    "secretgate: DISABLED for this session only, at your request — prompts, tool input and tool output are no longer scanned until the session ends (24 h at most).",
    directive.liftScope ? "The project scope is lifted too." : "A project scope, if any, stays enforced (type `/secretgate off scope` to lift it too).",
    "Type `/secretgate on` to turn it back on. A new session is protected automatically.",
  ].join(" ");
}
