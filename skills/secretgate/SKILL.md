---
name: secretgate
description: "Use to install, verify or manage the local secrets firewall for Claude Code, Codex CLI and OpenCode, or scan text/files/repos for leaked credentials. The bundled CLI runs without npm install. It masks detected secrets in supported tool output, restores placeholders on file writes, blocks secret-bearing Claude/Codex prompts and rewrites OpenCode prompts. Triggers include 'install secretgate', 'protect my secrets', 'secrets firewall', 'scan for secrets', and 'turn secretgate off for this session'."
license: MIT
metadata:
  version: 1.3.1
---

# Secretgate

Run commands from this skill's directory, or use the absolute path to its
`scripts/secretgate.mjs`. No npm installation or API key is required.

## Install or update

When asked to install or protect the user's agent:

1. Run `node scripts/secretgate.mjs status` to inspect the current installation.
2. Run `node scripts/secretgate.mjs init` to detect installed agents, install the
   bundled hooks/plugin and check their adapters. Use `init --all` when the user
   requests all three; individual flags are `--claude-code`, `--codex`, `--opencode`.
3. Read every agent's result. Report failures individually. Installation is
   complete when the requested integrations pass their local checks.
4. Tell the user to restart the affected agent sessions. Existing sessions do
   not reload hooks automatically. Local adapter checks do not prove an agent
   session has loaded them; never describe an untested session as verified.

For an audit, start with `status` and read-only checks. Installation is only
needed when requested or included in the task.

Install pins the CLI under `~/.secretgate/bin/` and copies a standalone plugin
into OpenCode's config directory. These survive eviction of the skill cache.
`--project` scopes only Claude Code settings to the current project.

## Everyday behavior

- Claude Code/Codex prompts containing detected secrets are blocked with a
  redacted copy to resend. OpenCode rewrites prompt text in place.
- Supported tool results are masked automatically. Claude Code uses a native
  output rewrite; Codex replaces the result with redacted hook feedback;
  OpenCode redacts tool results and restored arguments in model-bound history.
- File writes and edits restore known `SECRETGATE_…` placeholders locally,
  including Codex/OpenCode `apply_patch`. Claude Code's normal permission flow
  remains in force. Bash restoration stays off unless `restoreBash: true` is
  configured in `~/.secretgate/config.json`.
- Clean operations are silent. A normal Claude pre-tool hook returns `{}` so
  the regular permission flow continues.
- Sensitive reads are denied. Templates such as `.env.example` stay readable.
  `allow --path` exempts matching reads from the hook deny; tool output is still
  scanned. The agent's independent permission rules can still refuse a read.

## Exceptions and pauses

Prefer a targeted exception: inline `# pragma: allowlist secret` or
`gitleaks:allow`, then `allow <value>` (stored as SHA-256), then `allow --path
<glob>`. Disable a whole rule with `allow --rule <id>` only when appropriate.
Projects can add exceptions in `.secretgate.json`; OpenCode uses its project
directory, including when its server starts elsewhere.

`[allow-secret]` in a prompt bypasses that prompt's scan once.

When asked to pause protection, use the narrowest requested scope:

- `SECRETGATE_DISABLE=1 <agent>`: one process.
- `disable`: current indexed session, 60 minutes; directory fallback if no
  session is known. `--minutes N`, `--forever`, `--session` and `--project`
  provide explicit scopes/lifetimes; see `--help`.
- `enable` reverses the current pause; `enable --all` clears every pause.

State lives under `~/.secretgate/` (or `SECRETGATE_HOME`), never in a repository's
configuration. Restore, `scan` and `pipe` keep working while protection is paused.
Report the effective scope and expiry after changing a pause.

## Verification and limits

The repository's `pnpm run test:live` runs real CLI processes against a local
model endpoint and checks their outgoing requests using synthetic credentials.
It requires the three CLIs, but no model account. The separate
`tests/e2e/claude-code.sh` exercises the authenticated Claude service and defaults
to Fable 5.1. Distinguish these checks in reports.

- Coverage is limited to text, recognized secrets and events the agent emits.
  Images, screenshots, binary attachments, already-sent history and unsupported
  tool transports are outside coverage.
- Claude `@file` expansion can bypass tool hooks. Installed Read deny rules
  cover common sensitive paths, not every possible credential-bearing file.
- Failed MCP calls can bypass Codex's post hook. Raw tool output can remain in
  agents' local logs/telemetry even when model-bound output is masked.
- On an unscannable result, supported output envelopes are replaced by a safe
  notice. Claude stops when no valid replacement can be constructed and blocks
  subsequent prompts for the known session ID. Start a fresh session. If
  malformed input omits the session ID, automatic resume protection is unavailable.
- A process killed or timed out by the host can still fail open. Hook checks
  cannot provide an OS-level guarantee against all ways of reading a file.
- Claude can echo blocked prompts in local terminal/headless output. Treat that
  output as sensitive; it is not evidence of a model request.

`uninstall --<agent>` removes owned wiring and preserves unrelated settings and
the vault. Legacy Claude deny rules without ownership records are retained,
because their original owner cannot be determined safely.
