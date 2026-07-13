---
name: secretgate
description: "Use when the user wants to protect secrets/credentials from being sent to an LLM by a coding agent, install or manage a local secrets firewall, or scan text/files for leaked credentials. secretgate detects secrets (gitleaks-derived rules + entropy, zero-dependency engine) in prompts, file reads and tool output BEFORE they reach the LLM API, redacts them to stable placeholders (SECRETGATE_xxx) and restores the real values locally when the agent writes them back. Ships installers for Claude Code (hooks), OpenAI Codex CLI (hooks) and OpenCode (plugin). Triggers: 'protect my secrets', 'secrets firewall', 'stop sending credentials to the LLM', 'install secretgate', 'scan for secrets before sending'."
license: MIT
metadata:
  version: 0.0.0
---

# secretgate — local secrets firewall for coding agents

Placeholder — completed in M6 (install/status/allow flows, threat model).
