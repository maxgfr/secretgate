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
trust. Install the skill, then run `init` once:

```bash
npx skills add maxgfr/secretgate -g          # installs the skill globally
# then just tell your agent:  "install secretgate"
```

The skill activates on that ask and runs `secretgate init` for you — which
**auto-detects** Claude Code / Codex / OpenCode on this machine, wires each, and
then **proves the firewall fires** by spawning the real hook with a fake secret
(confirming the prompt is blocked and tool output is redacted) before declaring
success. Restart the agent session afterwards so the hooks load.

Prefer to run it yourself? The bundle lands next to the installed `SKILL.md`
(e.g. `~/.claude/skills/secretgate/scripts/secretgate.mjs`, or
`./.claude/skills/secretgate/…` for a project install):

```bash
node <skill-dir>/scripts/secretgate.mjs init
```

Once wired, protection is **fully automatic and deterministic**: the hooks — not
the model — scan and redact on every prompt and tool call. You never invoke
anything per-use.

## What it does

- **Detection engine**: 221 rules converted from [gitleaks](https://github.com/gitleaks/gitleaks)'
  default config (vendored, pinned, `pnpm run rules:sync` to refresh) + per-rule
  entropy thresholds + upstream stopword allowlists + secretgate built-ins for
  Luhn/IIN-gated credit cards, **URL-embedded credentials** (`postgres://user:pass@…`,
  basic-auth URLs) and **quoted passwords with punctuation** that gitleaks' generic
  rule misses. Zero runtime dependencies, single bundled `.mjs`, ~50ms per scan.
  If the real `gitleaks` binary is installed, `secretgate scan` runs it as a
  second engine (hybrid).
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
| Secret in **any** tool/bash/MCP output | ✅ redacted — PostToolUse fires on **every** tool (`*`) | ❌ upstream: output rewrite parsed but not applied | ✅ redacted (incl. grep/glob) |
| Placeholder written to a file | ✅ real value restored | ✅ real value restored | ✅ real value restored |
| Oversized / un-scannable output | ✅ **withheld** (fail-closed), never passed raw | ❌ (no output control) | plugin best-effort |

**Fail-closed by design.** If a scan crashes, times out against a crafted
payload, or the output is too large to scan, secretgate **withholds** the tool
output (a notice replaces it) rather than letting unscanned content through. A
per-scan wall-clock budget stops a maliciously slow payload from stalling a hook
past the agent's timeout (which would otherwise fail open).

**Not covered — know your residual risk:**

| Gap | Why | Mitigation |
|---|---|---|
| Claude Code `@file` mentions | inlined without firing tool hooks | `permissions.deny` rules (broadened to cover keys, `.aws`, `.ssh`, `credentials.json`, …) block the common sensitive files |
| Codex tool **output** | upstream can't rewrite tool output yet | prompts + tool inputs are protected; tool output is not — prefer Claude Code / OpenCode for output-heavy work |
| `codex exec` (non-interactive) | upstream bug: hooks don't fire (0.137–0.138) | interactive sessions only for now |
| Low-entropy secrets (`password: hunter2`) | indistinguishable from prose without huge false positives | catches strong/quoted passwords; use a real password manager |
| Restore → off-machine exfil | a prompt-injected agent could write a placeholder to a file (restored to the real value) then `git push` / upload it | Bash restore is **off** by default; the secret never reaches the model, only a file the agent already had write access to |
| Images / clipboard / screenshots | no hook surface | — |
| Secrets already in context before install | history is not rewritten | start a fresh session |

> A blocked prompt is never sent to the LLM, but Claude Code still echoes your
> `Original prompt:` back to your **local** terminal — that's your own input on
> your own screen, not exfiltration. The credential does not reach the API.
> The same echo lands in headless output (`claude -p --output-format json`,
> `result` field), so treat that output as sensitive before piping it to other
> systems.

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
secretgate init       Install for the agents on this machine + verify the firewall fires
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

- 160+ tests incl. per-event hook replays and a **zero-budget false-positive
  corpus** (lockfiles, minified JS, uuids, git logs, base64 blobs).
- A **differential CI job** runs the real gitleaks binary against the same
  payloads and requires the JS engine to find everything gitleaks finds
  (machine check on the Go→JS regex conversion).
- A **`skills-install` CI job**: `npx skills add` → run the bundle's `install`
  → hooks wired → a secret-bearing prompt is actually blocked (the whole
  no-npm distribution path).
- A **self-scan CI job**: secretgate scans its own repo → 0 findings.
- Verified against **real `claude -p` sessions** by inspecting the session
  transcript: a secret in a tool result never appears in what reached the
  model (only the placeholder does), and restore-on-write puts the real value
  on disk. E2E script: `tests/e2e/claude-code.sh`.

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
