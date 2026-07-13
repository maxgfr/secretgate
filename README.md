# secretgate

**Local secrets firewall for coding agents.** Detects credentials in prompts,
file reads and tool output **before they are sent to the LLM API**, redacts
them to stable placeholders, and restores the real values locally when the
agent writes them back. Works with **Claude Code**, **OpenAI Codex CLI** and
**OpenCode**. 100% local — no proxy, no network calls, no keys.

```
you paste a token in a prompt        -> BLOCKED, with a redacted copy to resend
the agent reads .env                 -> DENIED (the value never enters the model)
a bash command prints a credential   -> the model sees SECRETGATE_a1b2c3d4e5f6
the agent writes that placeholder
into a file                          -> the REAL value lands on disk
```

## Install

secretgate ships as an **agent skill** — there is no npm package to publish or
trust. One install, then a one-time wiring:

```bash
npx skills add maxgfr/secretgate                       # installs the skill + bundle
node .claude/skills/secretgate/scripts/secretgate.mjs install --all   # wires the hooks
node .claude/skills/secretgate/scripts/secretgate.mjs status          # doctor
```

Even simpler: after `npx skills add`, just tell your agent **"install
secretgate"** — the skill activates and runs the wiring for you. Restart the
agent session afterwards (hooks load at startup).

Once wired, protection is **fully automatic and deterministic**: the hooks — not
the model — scan and redact on every prompt and tool call. You never invoke
anything per-use.

## What it does

- **Detection engine**: 221 rules converted from [gitleaks](https://github.com/gitleaks/gitleaks)'
  default config (vendored, pinned, `pnpm run rules:sync` to refresh) + per-rule
  entropy thresholds + upstream stopword allowlists + a Luhn/IIN-gated
  credit-card rule. Zero runtime dependencies, single bundled `.mjs`, ~50ms per
  scan. If the real `gitleaks` binary is installed, `secretgate scan` runs it
  as a second engine (hybrid).
- **Redact-and-restore**: each secret maps to a stable `SECRETGATE_<hmac>`
  placeholder (per-install salt, vault at `~/.secretgate/vault.json`, 0600).
  The model only ever sees placeholders; consistent across sessions, restored
  on Write/Edit. Restoring inside Bash commands is **off by default** — a
  prompt-injected `curl $PLACEHOLDER` must not exfiltrate the real value.
- **Sensitive-file deny**: reads of `.env*`, `*.pem`, `*.key`, `id_rsa*`,
  `~/.aws/**`, `~/.ssh/**`, `~/.kube/config`, `.npmrc`, `.netrc`… are refused
  outright (`.env.example`/`.sample`/`.template`/`.dist` stay readable).
- **Standalone scanner**: `secretgate scan <dir>` (exit 1 on findings) doubles
  as a pre-commit hook; `secretgate pipe` redacts any stream.

## Coverage per agent (honest threat model)

| Surface | Claude Code | Codex CLI | OpenCode |
|---|---|---|---|
| Secret pasted in a prompt | ✅ blocked + redacted copy | ✅ blocked + redacted copy | ✅ redacted in place |
| Agent reads a sensitive file | ✅ hook deny + `permissions.deny` | ✅ hook deny | ✅ hook deny (`.env` also denied by OpenCode itself) |
| Secret in tool/bash output | ✅ redacted (`updatedToolOutput`) | ❌ upstream: output rewrite parsed but not applied | ✅ redacted (incl. grep/glob) |
| Placeholder written to a file | ✅ real value restored | ✅ real value restored | ✅ real value restored |

**Not covered — know your residual risk:**

| Gap | Why | Mitigation |
|---|---|---|
| Claude Code `@file` mentions | inlined without firing tool hooks | `permissions.deny` rules cover the common sensitive files |
| `codex exec` (non-interactive) | upstream bug: hooks don't fire (0.137–0.138) | interactive sessions only for now |
| Images / clipboard / screenshots | no hook surface | — |
| MCP tool traffic | not routed through these hooks | scope MCP servers carefully |
| Secrets already in context before install | history is not rewritten | start a fresh session |
| Agent-side hook timeout/kill | agents fail open by design | secretgate keeps p95 tiny; its own errors fail CLOSED on pre-events |

> A blocked prompt is never sent to the LLM, but Claude Code still echoes your
> `Original prompt:` back to your **local** terminal — that's your own input on
> your own screen, not exfiltration. The credential does not reach the API.

## False positives

Narrowest fix first:

1. inline `# pragma: allowlist secret` (or `# gitleaks:allow`) on the line
2. `secretgate allow <value>` — stored as SHA-256, never in clear
3. `secretgate allow --path 'tests/fixtures/**'`
4. `secretgate allow --rule <rule-id>` (last resort)
5. one-off prompt bypass: include `[allow-secret]` in the prompt

Projects can commit shared entries in `.secretgate.json`:
`{"allowlist": {"paths": ["testdata/**"]}}`.

## Commands

```
secretgate install    --claude-code|--codex|--opencode|--all [--project]
secretgate uninstall  (same flags — removes exactly what install added)
secretgate status     doctor: wiring, engines, vault health, limitations
secretgate scan       <file|dir|-> [--json] [--exclude <glob>]   exit 1 on findings
secretgate pipe       stdin -> stdout, secrets redacted
secretgate allow      <value> | --rule <id> | --path <glob>
secretgate vault      list | clear
secretgate hook       <agent> <event>        (internal hook entrypoint)
```

## How it's validated

- 140+ tests incl. per-event hook replays and a **zero-budget false-positive
  corpus** (lockfiles, minified JS, uuids, git logs, base64 blobs).
- A **differential CI job** runs the real gitleaks binary against the same
  payloads and requires the JS engine to find everything gitleaks finds
  (machine check on the Go→JS regex conversion).
- A **self-scan CI job**: secretgate scans its own repo → 0 findings.
- Manual E2E script against a live Claude Code session:
  `tests/e2e/claude-code.sh` (block / redact-in-transcript / restore-on-disk).

## Development

```bash
pnpm install
pnpm test                 # vitest
pnpm run rules:sync       # refresh rules/gitleaks.toml from upstream + regenerate
pnpm run check:build      # reproducible-bundle + fresh-rules gate
SECRETGATE_DIFFERENTIAL=1 pnpm exec vitest run tests/engine/differential.test.ts  # needs gitleaks
```

Distributed as a skill only — no npm package. Releases (GitHub, via
semantic-release) publish the install-free bundle as a release asset. The
`OpenCode` install writes a self-contained plugin file; there is no npm-pin mode.

MIT — rule definitions derived from [gitleaks](https://github.com/gitleaks/gitleaks) (MIT).
