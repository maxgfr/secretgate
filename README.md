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
the repo scopes the agent to src/,
and it reads docs/private.md         -> DENIED (out of scope, never sent)
```

## Install

There is no npm package to publish or trust. Pick one of two ways in, then run
`init` once.

**CLI (Homebrew, macOS and Linux)**: a standalone binary, no Node needed:

```bash
brew install maxgfr/tap/secretgate
secretgate init
```

**Agent skill**: install the skill and let the agent run `init`:

```bash
npx skills add maxgfr/secretgate -g          # installs the skill globally
# then just tell your agent:  "install secretgate"
```

`secretgate init` **auto-detects** Claude Code / Codex / OpenCode on this
machine, wires each, and then checks the installed adapters with synthetic
secrets. These local checks cover prompt masking/blocking, tool output and
OpenCode MCP/patch handling; they do not certify that an already-running agent
has loaded the hooks. Restart the agent session afterwards so the hooks load.

`init` pins a copy of the program that ran it under `~/.secretgate/bin/`
(`secretgate` for the binary, `secretgate.mjs` for the skill's Node bundle)
and the hooks run that copy, so they survive `brew upgrade`/`brew cleanup` and
evicted npx caches. Re-run `secretgate init` after an update to refresh it.
Both installs can coexist; the last `init` decides which one the hooks run.

With the skill and no Homebrew, run the bundle yourself. It lands next to the
installed `SKILL.md` (e.g. `~/.claude/skills/secretgate/scripts/secretgate.mjs`,
or `./.claude/skills/secretgate/…` for a project install):

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
  second engine and reports what it adds (`--no-gitleaks`, or `"hybrid": "off"`
  in `~/.secretgate/config.json`, to skip it). Hooks always use the JS engine only.
- **Redact-and-restore**: each secret maps to a stable `SECRETGATE_<hmac>`
  placeholder (per-install salt, vault at `~/.secretgate/vault.json`, 0600).
  The model only ever sees placeholders; consistent across sessions, restored
  on Write/Edit. Restoring inside Bash commands is **off by default** — a
  prompt-injected `curl $PLACEHOLDER` must not exfiltrate the real value.
- **Sensitive-file deny**: reads of `.env`, `.env.*`, `.envrc`, `*.pem`, `*.key`,
  `*.p12`/`*.pfx`, `id_rsa*`, `~/.aws/**`, `~/.ssh/**`, `~/.kube/config`, `.npmrc`,
  `.netrc`, `.git-credentials`, `.pgpass`, `.pypirc`, `*.tfstate`, `.dev.vars`,
  the secretgate vault… are refused outright (`.env.example`/`.sample`/`.template`/`.dist`
  stay readable). Paths are resolved first — `..`, `~`, symlinks and case
  variants all land on the same file. Files under test directories inside the
  project (`tests/`, `fixtures/`, `testdata/`, `__mocks__/`, `examples/`…) are
  **not** denied: fake keys there are what a security fix has to read, and their
  content is still redacted on the way to the model. In the shell, only
  commands that print, copy, upload or source a file count as reading it:
  `node --env-file=.env`, `docker compose --env-file .env`, `mv .env x`,
  `openssl genrsa -out server.key` are fine; `cat`, `cp`, `curl -d @.env`,
  `source .env`, `< .env` are not.
- **Project scope** (optional): a `.secretgate.json` can keep the agent inside
  some directories of the repository — see [Scope](#scope).
- **Standalone scanner**: `secretgate scan <dir>` (exit 1 on findings) doubles
  as a pre-commit hook; `secretgate pipe` redacts any stream. Files over 2 MB
  are skipped **and listed** on stderr (scan one with `secretgate scan - < FILE`);
  if the gitleaks binary fails, the JS engine's findings are still reported.

## Coverage per agent (honest threat model)

| Surface | Claude Code | Codex CLI | OpenCode |
|---|---|---|---|
| Secret pasted in a prompt | ✅ blocked + redacted copy | ✅ blocked + redacted copy | ✅ redacted in place |
| Agent reads a sensitive file | ✅ hook deny + `permissions.deny` | ✅ hook deny | ✅ hook deny (`.env` also denied by OpenCode itself) |
| Secret in tool/bash/MCP output | ✅ redacted — PostToolUse fires on **every** tool (`*`) | ✅ successful supported tools: raw result blocked, redacted result substituted | ✅ redacted (incl. grep/glob) |
| Placeholder written to a file | ✅ real value restored (built-in file tools; never through MCP tools, which may write remotely) | ✅ real value restored (`apply_patch`) | ✅ real value restored (built-in file tools) |
| Oversized / un-scannable output | ✅ **withheld** (fail-closed), never passed raw | ✅ **withheld** via block-and-replace | ✅ withheld on scan failure |
| Agent leaves the project [scope](#scope) | ✅ Read/Edit/Write/LS/Glob/Grep/Bash/MCP denied, search results filtered, `@path` blocked | ✅ shell/`apply_patch` denied | ✅ tools denied, glob/grep/list filtered, attachments removed |
| Agent tries to switch secretgate off | ✅ **asks you** first | ✅ refused — you run it | ✅ refused — you run it |

**Scan failures are explicit.** Supported output envelopes are replaced with a
withholding notice. If Claude Code cannot accept a safe replacement, Secretgate
stops the turn and blocks later prompts for that session ID; start a fresh
session. Malformed events without a session ID cannot be marked for this
resume protection. Host process kills/timeouts remain a fail-open limitation. A
per-scan wall-clock budget stops a maliciously slow payload from stalling a hook
past the agent's timeout (which would otherwise fail open).

**Not covered — know your residual risk:**

| Gap | Why | Mitigation |
|---|---|---|
| Claude Code `@file` mentions | inlined without firing tool hooks | the prompt hook checks every `@path` in the prompt: a sensitive file (`@.env`, `@server.pem`, `@credentials.json`; test fixtures exempt) blocks the prompt, and with a scope so does an out-of-scope one. `permissions.deny` rules add a native layer for real secret locations (`.env`, `.env.local`, `.envrc`, `~/.ssh`, `~/.aws`, `.netrc`, `.npmrc`, `.git-credentials`, the vault…); project-wide `*.pem`/`*.key` rules are not installed, since they cannot exempt fixtures (`init` removes the ones older versions added) |
| Shell commands are analysed, not sandboxed | `$(…)`, variables, `eval`, `python -c` hide paths from any static check | quotes, `cd`, redirections, globs and `x/../y` are resolved; `"bash": "strict"` refuses what cannot be checked; for a hard guarantee add the agent's OS sandbox (Claude Code sandbox, Codex permission profiles) |
| An agent running as you | it can reach anything your user can, given enough indirection | switching secretgate off from the agent needs your approval (Claude Code) or is refused (Codex, OpenCode); the OS sandbox is the hard boundary |
| Codex failed/unsupported tool output | `PostToolUse` only fires for successful supported tools; native output rewrite remains unsupported | Bash/apply_patch and successful MCP/local-function results are block-and-replace protected; an MCP result marked as an error can still bypass the post hook |
| Codex local telemetry/logs | block-and-replace changes the model-visible result, not Codex's local logging copy | the raw result stays local; protect access to Codex logs and telemetry configuration |
| Low-entropy secrets (`password: hunter2`) | indistinguishable from prose without huge false positives | catches strong/quoted passwords; use a real password manager |
| Passphrases with spaces (`password = "correct horse battery"`) | a spaced value after a `password` key is a UI label or a sentence far more often than a credential — 155 of 649 such matches on a 42k-file corpus were labels like `"password": "Client Secret"` | gitleaks' own generic rule stops at `[\w.=-]` for the same reason; use a real password manager |
| Restore → off-machine exfil | a prompt-injected agent could write a placeholder to a file (restored to the real value) then `git push` / upload it | Bash restore is **off** by default; the secret never reaches the model, only a file the agent already had write access to |
| Images / clipboard / screenshots | no hook surface | — |
| Secrets already in context before install | history is not rewritten | start a fresh session |
| A disabled run (see below) | you asked for it — nothing is scanned while it lasts | pauses expire on their own (60 min default, 24 h at most for a session pause), `status` leads with a banner, and no in-repo file can trigger one |

> A blocked prompt is never sent to the LLM, but Claude Code still echoes your
> `Original prompt:` back to your **local** terminal — that's your own input on
> your own screen, not exfiltration. The credential does not reach the API.
> The same echo lands in headless output (`claude -p --output-format json`,
> `result` field), so treat that output as sensitive before piping it to other
> systems.

## False positives

Narrowest fix first:

1. inline `# pragma: allowlist secret` (or `# gitleaks:allow`) on the line —
   honored by `secretgate scan`, **not** by the hooks: text on its way to the
   model (a fetched page, a tool result) could carry a forged pragma
2. `secretgate allow <value>` — stored as SHA-256, never in clear
3. `secretgate allow --path 'tests/fixtures/**'`
4. `secretgate allow --rule <rule-id>` (last resort)
5. one-off prompt bypass: include `[allow-secret]` in the prompt (it exempts
   what you typed, never content attached to the prompt)
6. whole firewall off for one run: say "désactive secretgate" (see below)

Projects can commit shared entries in `.secretgate.json`:
`{"allowlist": {"paths": ["testdata/**"]}}`. `secretgate scan` always honors
them (the repository describing its own fixtures). The **hooks** honor them only
after you run `secretgate trust` in that repository — and again after every
edit of the file — so a repository you clone cannot allowlist every rule and
quietly switch detection off for itself. `secretgate status` lists untrusted files.

## Turning it off for one run

Sometimes you *are* working on the credentials — debugging an auth flow, an
incident, a fixtures repo. The quickest way is to **say so in the conversation**,
on a line of its own:

```
désactive secretgate            (or: disable secretgate / secretgate off)
désactive secretgate et le scope   (also lifts the project scope)
réactive secretgate             (or: enable secretgate / secretgate on)
/secretgate disable             the skill, by name (Codex: $secretgate disable)
/secretgate disable scope       … also lifting the scope;  /secretgate enable to undo
```

That pauses **this session only**, from that very prompt on, until the session
ends (24 h at most); a new conversation is protected again. Claude Code shows a
confirmation; on OpenCode it is added to the prompt; Codex applies it silently
(`secretgate status` shows it). Only prompts you submit are read, and only a
line that *is* the instruction counts — "how do I disable secretgate?" does not.
The skill form is applied by the same prompt hook before the skill even loads,
so the agent has nothing to run and nothing to approve; the skill then just
confirms with `secretgate status`. `pnpm test:live` checks this on all three
agents.

From a terminal, three scopes, narrowest first:

```bash
SECRETGATE_DISABLE=1 claude       # one process. No state, dies with the shell.
secretgate disable                # this agent run, 60 min (--minutes N | --forever)
secretgate disable --session      # this agent run, for its whole lifetime (no timer)
secretgate disable --project      # this directory tree, until `enable --project`
secretgate disable --scope …      # any of the above, also lifting the project scope
secretgate enable                 # back on   (--all clears every pause)
```

If the **agent** runs `secretgate disable` (or `allow`, `trust`, `uninstall`,
or changes `~/.secretgate/`, `.secretgate.json` or its own hook settings — with an
editor, a redirection, `sed -i`, `perl -pi`, `dd of=`…),
Claude Code asks you first; Codex and OpenCode cannot ask from a hook, so they
refuse and tell you to run it yourself — or to say "désactive secretgate".

`secretgate disable` with no flag pauses the **agent session** running in this
directory — another session in the same repo stays protected. Run it from the
agent's own shell to pause exactly that run. A pause **expires on its own**, and
`secretgate status` leads with a loud banner while any of them is active.

`secretgate disable --session` pauses that same run for the **session's
lifetime** instead of a fixed 60 minutes: it ends with the run (a new
conversation is protected automatically), with a 24 h ceiling in case the run
is resumed for days. `secretgate enable --session` turns it back on now.
"Most recent session" means the one that last received a prompt, so running it
from the session you are talking to pauses that one.

Three things a disable never switches off: **placeholder restore** (otherwise the
agent would write dead `SECRETGATE_…` tokens into your files), the standalone
`scan` / `pipe` commands (running one is the intent), and the **project scope**
unless you add `--scope` (or say "… et le scope").

> The off switch lives in `~/.secretgate/` and **only** there. A
> `.secretgate.json` in a repository cannot disable the firewall, and its
> allowlist only reaches the hooks once you `secretgate trust` it — otherwise
> any repo you cloned could ship its own kill switch.

## Scope

Keep the agent inside part of a repository, so content outside it is never sent
to the model. Declare it in the project's `.secretgate.json`:

```jsonc
{
  // comments and trailing commas are fine (JSONC)
  "scope": {
    "allow": ["src/**", "tests/**", "package.json"], // present → everything else is out
    "deny":  ["src/legacy/**"],                       // wins over allow
    "bash":  "paths",                                 // "paths" (default) | "strict"
    "temp":  true                                     // OS temp dirs are scratch space (default)
  }
}
```

- **Root**: the directory holding the `.secretgate.json`. It is found from the
  agent's working directory upwards, up to the repository root, so a session
  started in `src/` sees it too. The directory the Claude Code session was
  started in (`CLAUDE_PROJECT_DIR`) is always searched as well, so a `cd` into
  a submodule or a nested repository does not drop the project's scope. If
  several files declare a scope, all apply (a path must satisfy each).
- **Globs** are relative to the root (`*`, `**`, `?`, `{a,b}`); `src` and
  `src/**` both cover the whole directory. Absolute or `~/` globs are allowed.
  With an `allow` list, anything outside the root is out of scope — except the
  OS temp dirs (`cmd > /tmp/log; tail /tmp/log`), unless `"temp": false`.
- **Paths are resolved first**: `~`, `~+`, `..`, symlinks (a link in `src/`
  pointing at `secret/` is out), `/var` vs `/private/var`, and case on
  macOS/Windows.
- **What is checked**:
  - reads, edits and writes (Read/Edit/Write/MultiEdit/NotebookEdit/`apply_patch`,
    MCP tools naming existing paths, including move/copy `source`/`destination`);
  - listings: a directory leading to allowed paths may be listed, and `cd`
    targets are checked the same way;
  - Glob/Grep: refused on an unrelated root, results filtered otherwise
    (Glob lists, grep lines, directory trees);
  - every path of every shell command — redirections, globs, `$'…'`,
    `git show HEAD:path`, and `bash -c '…'` scripts, which are analysed in place;
  - recursive readers (`grep -r`, `rg`, `find`, `ls -R`, `tree`, `tar c`,
    `git diff`/`show`/`log -p` without pathspec) against the files actually
    below their target: refused only if one of them is out of scope, with a
    hint naming a directory that is fully in scope;
  - `@path` mentions in the prompt (Claude Code/Codex block the prompt,
    OpenCode removes the attachment). `@docs team` is prose; a directory
    mention is written `@docs/`.
- **Normal project work keeps working** in the default `"bash": "paths"` mode:
  project-wide tools that take a directory (`tsc -p .`, `biome check .`,
  `go test ./...`) count as listings, and a program an interpreter runs
  (`node node_modules/x/cli.js`, `python tools/gen.py`) is executed, not
  printed. `"bash": "strict"` treats both as full reads, and additionally
  refuses what cannot be checked statically: `$(…)`, backticks, variables,
  `eval`, `python -c`, `node -e`, `xargs`, `find -exec`…
- **The fence cannot be moved from inside**: while a scope is active, any
  `.secretgate.json`, `.claude/settings*.json`, Codex and OpenCode
  configuration and secretgate's own state are read-only for the agent. The
  policy stays readable (`cat .secretgate.json`), and secretgate's own CLI
  (`secretgate scope`, `status`) always runs.
- **A pause keeps the scope** (it switches off secret scanning, not the
  boundary): lift it with `secretgate disable --scope`, `/secretgate disable
  scope` or "désactive secretgate et le scope", or edit `.secretgate.json`
  yourself.
- **An invalid `.secretgate.json`** (broken JSON, `"allow": "src/**"`, unknown
  keys in `scope`…) makes every tool call fail closed — except reading and
  editing that file (the edit asks for your approval) — until it is fixed: it
  might have held a scope.

`secretgate scope` prints the effective scope; `secretgate scope check <path…>`
exits 1 if any path is outside it (handy in scripts and CI).

Compared with the agents' own `permissions.deny`: one file for three agents,
an allow-list rather than a deny-list, and it also covers shell commands, search
results and `@mentions`. It is still a static check of what the agent asks to
do, not an OS sandbox — pair it with the agent's sandbox when you need a hard
guarantee.

## Commands

```
secretgate init       Install for the agents on this machine + verify the firewall fires
secretgate install    --claude-code|--codex|--opencode|--all [--project]
secretgate uninstall  (same flags — removes exactly what install added)
secretgate status     doctor: wiring, engines, vault health, limitations
secretgate scan       <file|dir|-> [--json] [--exclude <glob>] [--no-gitleaks]   exit 1 on findings
secretgate pipe       stdin -> stdout, secrets redacted
secretgate allow      <value> | --rule <id> | --path <glob>
secretgate trust      [--revoke]   let the hooks honor this repo's .secretgate.json allowlist
secretgate scope      [check <path…>]   show the project scope / exit 1 if a path is outside it
secretgate vault      list | clear
secretgate disable    [--minutes N | --forever | --session] [--project] [--session <id>] [--scope]
secretgate enable     [--project] [--session [id]] [--all]
secretgate hook       <agent> <event>        (internal hook entrypoint)
```

Environment: `SECRETGATE_HOME` (state dir, default `~/.secretgate`),
`SECRETGATE_DISABLE=1` (firewall off for this process).

## How it's validated

- 450+ tests incl. per-event hook replays for all three hosts, the shell
  analyser, the scope, known bypass regressions, and a **zero-budget
  false-positive corpus** (lockfiles, minified JS, uuids, git logs, base64
  blobs). CI enforces a coverage floor on `src/`.
- A **differential CI job** runs the real gitleaks binary against the same
  payloads and requires the JS engine to find everything gitleaks finds
  (machine check on the Go→JS regex conversion).
- A **`skills-install` CI job**: `npx skills add` → run the bundle's `install`
  → adapters installed → a secret-bearing prompt is actually blocked (the whole
  no-npm distribution path).
- A **`binary-smoke` CI job** (Linux and macOS): compile the standalone binary,
  `init --all` in a throwaway home, and require every hook to run the pinned
  binary and block a secret with no `node` on `PATH`.
- A **self-scan CI job**: secretgate scans its own repo → 0 findings.
- Verified against **real `claude -p` sessions** by inspecting the session
  transcript: a secret in a tool result never appears in what reached the
  model (only the placeholder does), and restore-on-write puts the real value
  on disk. E2E script: `tests/e2e/claude-code.sh`.

## Integration verification

`pnpm run test:live` launches the actual Claude Code, Codex and OpenCode binaries
against a loopback model endpoint. It inspects outgoing requests for synthetic
secrets and confirms restore-on-write on disk, including MCP results. No model
account is needed. `node tests/e2e/live-agents.mjs codex` selects one agent.

`bash tests/e2e/claude-code.sh` additionally uses an authenticated Claude account
and defaults to `claude-fable-5-1` (`SECRETGATE_TEST_MODEL` overrides it). This
service test complements the deterministic request-capture tests.

Clean hooks are silent. Path exceptions lift Secretgate's read denial while
keeping output redaction; the agent's own permissions can still deny access.
OpenCode also scans tool history before model conversion, including restored
write arguments and errors. Disabling protection intentionally skips this scan.

Install/uninstall preserve existing rules and foreign hooks. Claude ownership
is recorded beside settings; legacy rules without an ownership record are
retained on uninstall. `status` checks Codex trust definitions as well as wiring.

## Development

```bash
pnpm install
pnpm test                 # vitest
pnpm run rules:sync       # refresh rules/gitleaks.toml from upstream + regenerate
pnpm run check:build      # reproducible-bundle + fresh-rules gate
SECRETGATE_DIFFERENTIAL=1 pnpm exec vitest run tests/engine/differential.test.ts  # needs gitleaks
pnpm run build && pnpm run build:binaries --native   # needs Bun; dist/secretgate-<platform>-<arch>
pnpm run smoke:binary dist/secretgate-macos-arm64    # init + hooks through the binary, no node on PATH
```

Distributed as a skill and a Homebrew binary — no npm package. Releases
(GitHub, via semantic-release) publish the install-free bundle plus the
Bun-compiled binaries for macOS and Linux (arm64, x64) with their
`SHA256SUMS`; the [tap](https://github.com/maxgfr/homebrew-tap) installs those.
The `OpenCode` install writes a self-contained plugin file (embedded in the
binary); there is no npm-pin mode.

MIT — rule definitions derived from [gitleaks](https://github.com/gitleaks/gitleaks) (MIT).

## Automatic or manual

`secretgate` is **automatic by default**, and that is the point of it.
One `secretgate init` wires the hooks into Claude Code, Codex and
OpenCode, and from then on every prompt, file read and tool result is
scanned and redacted by the hooks — not by the model, and not on request.
Turning the firewall off is saying "désactive secretgate", `secretgate disable`
for a run, or removing the hooks; nothing about it depends on a skill being invoked.

The shipped skill is also model-invocable, so the agent can reach
`secretgate`'s own commands when a task calls for them. You keep both switches:

| Host | Shipped, automatic | Explicit-only |
| --- | --- | --- |
| Claude Code | no `disable-model-invocation` in `SKILL.md` | add `disable-model-invocation: true` |
| Codex | `allow_implicit_invocation: true` under `policy:` in `agents/openai.yaml` | set it to `false` |
| OpenCode | `metadata.opencode/autoinvoke: 'true'` in `SKILL.md` | set it to `'false'` |

Claude Code can do it without touching the file:
`"skillOverrides": { "secretgate": "user-invocable-only" }` in `settings.json`
leaves `/secretgate` working while hiding the skill from the model. Plugin installs
ignore `skillOverrides`, so edit the frontmatter there. Updating or reinstalling
restores the shipped default, so reapply the change afterwards.

OpenCode V1 reads no `autoinvoke` metadata; `permission.skill` in
`~/.config/opencode/opencode.json` or the project configuration is how you force
explicit-only there. Retain unrelated permissions:

```json
{
  "permission": {
    "skill": {
      "secretgate": "deny"
    }
  }
}
```

On OpenCode 1.18.30 that rule hides the skill from the agent and rejects
skill-tool loading, while the explicit `/secretgate` command still works.
Installation with `skills add` does not write this OpenCode V1 configuration.
