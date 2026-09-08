# Integration verification

Validated locally on macOS with Node 24.19.0 and the install-free bundle on
Node 18.17.0 (the declared minimum). The CI workflow repeats the portable
runtime checks on Linux, macOS and Windows. Real agent process tests run on
Linux and macOS; Windows coverage is limited to the bundle and installers.

| Agent | Version | Checks |
| --- | --- | --- |
| Claude Code | 2.1.263 | Prompt interception, native Read/Write round trip, MCP output, outgoing model requests |
| Codex CLI | 0.153.4 | Prompt interception, shell/apply_patch round trip, MCP output, outgoing model requests, symlinked config trust |
| OpenCode | 1.18.29 | Prompt rewrite, read/write round trip, MCP output, restored arguments remasked in outgoing history |

The deterministic tests use a loopback model endpoint and synthetic tokens.
They assert that outgoing requests contain no raw fixture token, that the next
request contains a placeholder, and that writes restore the value on disk.
They do not require an authenticated model account.

An additional authenticated Claude Code run using `claude-fable-5-1` passed the
three service scenarios in `tests/e2e/claude-code.sh`. A separate Fable 5.1 review
identified output-envelope, mixed-result and permission-flow issues addressed
by this patch. This model review complements executable checks; it is not a
guarantee of exhaustive protection.

Reproduce the checks:

```sh
pnpm run typecheck
pnpm run lint
pnpm run test:coverage
SECRETGATE_DIFFERENTIAL=1 pnpm test # requires gitleaks
pnpm run check:build              # bundles must match the index/commit
pnpm run test:live                # requires all three agent CLIs
node tests/e2e/runtime.mjs
node tests/e2e/skills-install.mjs  # exercises npx skills add for each agent
bash tests/e2e/claude-code.sh      # authenticated Fable 5.1 service test
node scripts/secretgate.mjs scan .
```

The differential run passes 324 tests; the optional external-corpus test remains
skipped without its separately supplied dataset. Clean Claude hook execution
measured a 24 ms median and 26 ms p95 across 25 local samples; these figures
are machine-specific, not a performance guarantee.

Tests cover normal permission abstention, scoped exceptions/pauses, preservation
of foreign settings, malformed/oversized output, shared text budgets and binary
attachments. Limits still include images, unrecognized secrets, old history,
host timeouts, Claude `@file` expansion and Codex failed MCP calls that do not
emit a post hook. See the skill's verification section before claiming coverage
for another transport or agent version.
