// OpenCode plugin entrypoint — bundled standalone as scripts/secretgate-opencode.mjs.
// Filled in at M4: chat.message (in-place prompt redaction), tool.execute.before
// (deny sensitive reads + placeholder restore), tool.execute.after (output redaction).
export const SecretgatePlugin = async (_ctx: unknown) => {
  return {};
};
