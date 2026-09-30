import { addPause, removePause } from "./disable.js";

// Turning secretgate off by saying so. The user types "désactive secretgate"
// (or "disable secretgate") in the conversation and THIS session is paused
// until it ends — no command for the agent to run, so the agent itself never
// needs the power to switch its own firewall off (an agent-run `secretgate
// disable` asks for approval instead, see hooks/policy.ts).
//
// Only prompts the user submits are read (UserPromptSubmit / chat.message),
// never tool output. To keep a discussion ABOUT the feature from triggering
// it, the directive must be an instruction on a line of its own:
//   désactive secretgate            disable secretgate
//   désactive secretgate et le scope   (also lifts the project scope)
//   réactive secretgate             enable secretgate
//   /secretgate disable [scope]     /secretgate enable   (the skill, by name)
// Short courtesy words around it are fine ("stp", "please", "pour cette
// session"); a longer sentence is not an instruction and is ignored.

export type PromptDirective = { action: "disable"; liftScope: boolean } | { action: "enable" };

const NAME = String.raw`[\`'"]?secretgate[\`'"]?`;
const COURTESY = String.raw`(?:(?:stp|svp|please|pls|merci|thanks|now|maintenant|ok|okay)[\s,.!]*)*`;
const TAIL = String.raw`(?:\s+(?:pour|for)\s+(?:cette|ce|this|la|the)\s+(?:session|run|conversation|conv))?(?:\s+(?:stp|svp|please|merci|thanks))?\s*[.!]*`;
const SCOPE = String.raw`(?:\s+(?:et|and|\+|avec|with|,)\s*(?:le|la|the)?\s*(?:scope|p[ée]rim[èe]tre))?`;

const DISABLE = new RegExp(
  String.raw`^${COURTESY}(?:d[ée]sactiv(?:e|er|ez)|coupe(?:r|z)?|mets\s+en\s+pause|disable|turn\s+off|switch\s+off|pause)\s+(?:le\s+|la\s+|the\s+)?${NAME}(${SCOPE})${TAIL}$|^${COURTESY}(?:turn\s+|switch\s+)?${NAME}\s*:?\s*off${TAIL}$`,
  "i",
);
const ENABLE = new RegExp(
  String.raw`^${COURTESY}(?:r[ée]activ(?:e|er|ez)|rallume(?:r|z)?|enable|re-?enable|turn\s+(?:back\s+)?on|resume)\s+(?:le\s+|la\s+|the\s+)?${NAME}(?:\s+back\s+on)?${TAIL}$|^${COURTESY}(?:turn\s+|switch\s+)?${NAME}\s*:?\s*(?:back\s+)?on${TAIL}$`,
  "i",
);

// The skill invoked by name with an argument: `/secretgate disable` (Claude
// Code, OpenCode) or `$secretgate disable` (Codex). The hook sees the raw
// prompt before the skill loads, so the pause is already in place when the
// agent reads SKILL.md — the agent never has to run anything.
const SKILL_DISABLE =
  /^[/$]secretgate\s+(?:disable|off|pause|stop|d[ée]sactiv(?:e|er|ez)?|coupe)(\s+(?:--)?(?:scope|p[ée]rim[èe]tre)|\s+(?:et|and|\+)\s+(?:le\s+|la\s+|the\s+)?(?:scope|p[ée]rim[èe]tre))?\s*[.!]*$/i;
const SKILL_ENABLE = /^[/$]secretgate\s+(?:enable|on|resume|r[ée]activ(?:e|er|ez)?|rallume)\s*[.!]*$/i;

export function promptDirective(prompt: string): PromptDirective | undefined {
  for (const raw of prompt.split(/\r?\n/)) {
    // `opencode run "/secretgate disable"` delivers the message still quoted.
    const line = raw
      .trim()
      .replace(/^(["'`])(.*)\1$/, "$2")
      .trim();
    if (line.length === 0 || line.length > 120) continue;
    const skillOff = SKILL_DISABLE.exec(line);
    if (skillOff) return { action: "disable", liftScope: Boolean(skillOff[1]) };
    if (SKILL_ENABLE.test(line)) return { action: "enable" };
    const off = DISABLE.exec(line);
    if (off) return { action: "disable", liftScope: Boolean(off[1]) };
    if (ENABLE.test(line)) return { action: "enable" };
  }
  return undefined;
}

/** Apply a directive for one session. Returns the message to show the user. */
export function applyPromptDirective(directive: PromptDirective, sessionId: string | undefined, cwd: string | undefined): string {
  if (!sessionId) {
    return "secretgate: this agent did not report a session id, so it cannot be paused from the conversation — run `secretgate disable --session` in a terminal instead.";
  }
  if (directive.action === "enable") {
    const cleared = removePause("session", sessionId);
    return cleared.length > 0
      ? "secretgate: re-enabled for this session, at your request. Prompts, tool input and tool output are scanned again."
      : "secretgate: already active for this session.";
  }
  addPause({ scope: "session", target: sessionId, minutes: null, cwd, lifetime: true, liftScope: directive.liftScope });
  return [
    "secretgate: DISABLED for this session only, at your request — prompts, tool input and tool output are no longer scanned until the session ends (24 h at most).",
    directive.liftScope
      ? "The project scope is lifted too."
      : "A project scope, if any, stays enforced (say “désactive secretgate et le scope” to lift it too).",
    "Say “réactive secretgate” to turn it back on. A new session is protected automatically.",
  ].join(" ");
}
