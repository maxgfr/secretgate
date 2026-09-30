---
name: secretgate
description: Install, verify, and manage Secretgate protections or scan text, files, and repositories for exposed credentials.
license: MIT
metadata:
  version: 1.5.1
  opencode/autoinvoke: 'true'
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
- Sensitive reads are denied, including through shell commands, symlinks and
  `..` paths. Templates such as `.env.example` stay readable, and so do files
  under test directories (`tests/`, `fixtures/`, `testdata/`…): fake keys there
  are readable for security work, and their content is still redacted.
- After updating secretgate, run `init` again: it refreshes the hook matcher
  and drops deny rules older versions installed (`status` flags both).
  `allow --path` exempts matching reads from the hook deny; tool output is still
  scanned. The agent's independent permission rules can still refuse a read.

## Exceptions and pauses

Prefer a targeted exception: inline `# pragma: allowlist secret` or
`gitleaks:allow` (honored by `scan`, not by the hooks), then `allow <value>`
(stored as SHA-256), then `allow --path <glob>`. Disable a whole rule with
`allow --rule <id>` only when appropriate. Projects can add exceptions in
`.secretgate.json`; `scan` always honors them, the hooks only after the user
runs `trust` in that repository (again after each edit). OpenCode uses its
project directory, including when its server starts elsewhere.

`[allow-secret]` in a prompt bypasses that prompt's scan once. It covers what
the user typed, not attached file content.

### Disable or enable through this skill

When invoked as `/secretgate disable` (Codex: `$secretgate disable`; also
`désactive`, `off`, `disable scope`) or `/secretgate enable` (`réactive`, `on`),
the prompt hook has already applied it to this session before you read this.
Do not run `disable` yourself.

1. Run `node scripts/secretgate.mjs status` (read-only) and report what it says:
   the pause, its bound (until the session ends, 24 h at most), and whether the
   project scope was lifted.
2. Only if `status` shows this session is not paused (the hooks are not wired
   or are older than this skill), run
   `node scripts/secretgate.mjs disable --session` (`--scope` when asked). Claude
   Code asks the user to approve it; that is expected. On Codex/OpenCode it is
   refused, so tell the user to run it themselves (`! secretgate disable --session`).

The same works without the skill: the user writes, on its own line,
`désactive secretgate` (or `disable secretgate`), `réactive secretgate`, or
`désactive secretgate et le scope`. The pause covers this session only, until it
ends (24 h at most).

From a terminal, use the narrowest requested scope:

- `SECRETGATE_DISABLE=1 <agent>`: one process.
- `disable`: current indexed session, 60 minutes; directory fallback if no
  session is known. `--minutes N`, `--forever`, `--session`, `--project` and
  `--scope` (also lift the project scope) are explicit options; see `--help`.
- `enable` reverses the current pause; `enable --all` clears every pause.

When you run `disable`, `allow`, `trust` or `uninstall` yourself, Claude Code
asks the user to approve; Codex and OpenCode refuse. That is intended: turning
the firewall off is the user's decision. Do not work around it. Ask the user
to approve, to say `désactive secretgate`, or to run the command themselves.

State lives under `~/.secretgate/` (or `SECRETGATE_HOME`), never in a repository's
configuration. Restore, `scan` and `pipe` keep working while protection is paused.
Report the effective scope and expiry after changing a pause.

## Project scope

A `scope` in the project's `.secretgate.json` fences the agent into part of
the repository:

```json
{ "scope": { "allow": ["src/**", "tests/**"], "deny": ["src/legacy/**"], "bash": "paths" } }
```

`deny` wins over `allow`. With `allow`, everything else is out, including paths
outside the repository (OS temp dirs excepted unless `"temp": false`). The file
accepts comments. Reads, edits, listings, searches, shell commands, MCP
path arguments and `@path` prompt mentions are checked. `"bash": "strict"` also
refuses commands whose paths cannot be known statically. While a scope is active,
the files that define it are read-only for the agent. A pause keeps the scope
unless it lifts it explicitly.

- `scope` prints the effective scope and `scope check <path…>` exits 1 on any
  out-of-scope path. Use them before planning work in a scoped repository.
- When a call is refused as out of scope, do not look for another route to the
  same content. Say what you needed and let the user widen the scope.
- Shell analysis is best effort. Recommend the agent's OS sandbox when the user
  needs a hard guarantee.

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
