---
name: secretgate
description: "Use when the user wants to protect secrets/credentials from being sent to an LLM by a coding agent, install or manage a local secrets firewall, or scan text/files/repos for leaked credentials. secretgate detects secrets (221 gitleaks-derived rules + entropy + Luhn, zero-dependency engine, `node scripts/secretgate.mjs`) in prompts, file reads and tool output BEFORE they reach the LLM API, redacts them to stable placeholders (SECRETGATE_xxx) and restores the real values locally when the agent writes them back to files. Ships installers for Claude Code (hooks), OpenAI Codex CLI (hooks) and OpenCode (plugin). Triggers: 'protect my secrets', 'secrets firewall', 'stop sending credentials to the LLM', 'install secretgate', 'scan for secrets', 'redact secrets before sending', 'block credentials in prompts'."
license: MIT
metadata:
  version: 1.1.4
---

# secretgate — local secrets firewall for coding agents

A credential must never travel to an LLM API. secretgate enforces that locally,
with a deterministic engine (`node scripts/secretgate.mjs`, no npm install, no
keys): 221 rules converted from gitleaks + entropy gates + Luhn-checked cards.
Where the agent's hook API allows rewriting, secrets are **redacted to stable
placeholders** and **restored locally** when the agent writes them back
(redact-and-restore); where it only allows blocking (prompts on Claude
Code/Codex), the prompt is **blocked with a redacted copy** to resend.

## Activation → install (do this first when the skill triggers)

When this skill activates (the user asks to protect secrets / install
secretgate / set up the firewall), run the doctor, then wire whatever is not
yet wired. secretgate is a skill, not an npm package — you run its own bundle:

```bash
node scripts/secretgate.mjs status                  # what is already wired
node scripts/secretgate.mjs install --claude-code   # hooks + permissions.deny in ~/.claude/settings.json
node scripts/secretgate.mjs install --codex         # ~/.codex/hooks.json + [features] hooks = true
node scripts/secretgate.mjs install --opencode      # self-contained plugin in ~/.config/opencode/plugin/
node scripts/secretgate.mjs install --all           # all three
```

`--project` scopes the Claude Code install to `./.claude/settings.json`.
`install` pins a copy of the bundle under `~/.secretgate/bin/` and wires the
agent to call THAT, so it keeps working after the skill cache is evicted. Always
tell the user to RESTART the agent session afterwards — hooks load at startup.
Once wired, redaction is automatic and deterministic (the hook does it, not you).

## Commands

| Command | What it does |
|---|---|
| `status` | Doctor: per-agent wiring, engine, vault health, limitations |
| `scan <file\|dir\|->` | Scan for secrets (exit 1 on findings; `--json`; never prints raw secrets) |
| `pipe` | stdin -> stdout with secrets redacted to placeholders |
| `allow <value>` / `allow --rule <id>` / `allow --path <glob>` | Allowlist (values stored as SHA-256, never in clear) |
| `vault list` / `vault clear` | Inspect placeholder mappings (never shows secrets) |
| `uninstall --<agent>` | Remove exactly what install added |

## How the protection works (tell the user when asked)

- **Prompts**: Claude Code/Codex → blocked with a redacted copy (add
  `[allow-secret]` to bypass once). OpenCode → silently redacted in place.
- **File reads**: `.env*`, keys, `~/.aws`, `~/.ssh`… are denied outright
  (`.env.example`/`.sample`/`.template` stay readable). The value never enters
  the model.
- **Tool/bash output**: redacted to `SECRETGATE_<hash>` placeholders (Claude
  Code + OpenCode; Codex cannot rewrite output yet).
- **Restore**: when the agent writes a placeholder into a file (Write/Edit),
  the REAL value lands on disk. Bash restore is OFF by default
  (prompt-injection exfiltration guard) — enable with `restoreBash: true` in
  `~/.secretgate/config.json`.
- **Clean tool calls**: the Claude Code pre-tool-use hook answers minimal JSON
  (`{}`, decision-free = normal permission flow) instead of empty stdout.
  Empty hook output triggers a Claude Code bug (anthropics/claude-code#77782)
  that forces an interactive permission prompt on every matched tool call,
  even in auto mode — and the documented `"defer"` decision value is rejected
  by Claude Code <= 2.1.212, so `{}` is the abstain that works everywhere.

## NOT covered (be honest with the user)

- Claude Code `@file` mentions inline content without firing tool hooks
  (permissions.deny rules are the only cover there).
- Codex non-interactive runs (`codex exec`) — upstream bug, hooks don't fire.
- Images/screenshots/clipboard, MCP tool traffic, and anything already in the
  conversation before install.
- If a hook process is killed/times out, the agent proceeds (agent-side
  fail-open); secretgate itself fails CLOSED on its own errors for pre-events.
- A blocked prompt is echoed back locally by Claude Code (`Original prompt:`
  in the terminal and in `claude -p` JSON `result`) — the API never sees it,
  but treat piped headless output as sensitive.

## False positives

Prefer the narrowest fix: inline `# pragma: allowlist secret` (or
`gitleaks:allow`) on the line → `allow <value>` (hashed) → `allow --path
<glob>` → `allow --rule <id>` (last resort). A project can commit extra
allowlist entries in `.secretgate.json` (`{"allowlist": {"paths": […]}}`).
