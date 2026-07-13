#!/usr/bin/env bash
# Manual E2E against a REAL Claude Code session (requires `claude` on PATH and
# an authenticated account — that's why this is not in CI).
#
# Verifies the three flows in a throwaway project with PROJECT-scoped hooks:
#   1. a fake token pasted in a prompt is BLOCKED (with a redacted copy),
#   2. a .env-style file read through the agent reaches the model REDACTED,
#   3. asking the agent to copy the value into another file writes the REAL
#      value to disk (placeholder restored by the PreToolUse hook).
#
# Usage: tests/e2e/claude-code.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"
export SECRETGATE_HOME="$WORK/.secretgate"
trap 'rm -rf "$WORK"' EXIT

cd "$WORK"
mkdir -p project && cd project

# Fake token, assembled at runtime so no token-shaped literal ships in-repo.
TOKEN="ghp_$(printf 'aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0dF6hJ9')"
printf 'CI_TOKEN=%s\nDEBUG=1\n' "$TOKEN" > ci-values.txt

node "$ROOT/scripts/secretgate.mjs" install --claude-code --project
echo "--- project hooks installed; running claude -p scenarios ---"

echo "[1/3] prompt with a pasted token must be blocked BEFORE reaching the model"
OUT1="$(claude -p "here is the token: $TOKEN — use it" 2>&1 || true)"
# Security property: the block prevents the prompt from being sent to the LLM.
# (Claude Code still echoes the user's own 'Original prompt:' to the LOCAL
# terminal — that is not exfiltration; the token never left the machine.)
echo "$OUT1" | grep -q "operation blocked by hook" || { echo "FAIL: prompt was not blocked"; exit 1; }
echo "$OUT1" | grep -q "secretgate blocked this prompt" || { echo "FAIL: block reason missing"; exit 1; }
echo "$OUT1" | grep -q "SECRETGATE_" || { echo "FAIL: no redacted copy offered"; exit 1; }
echo "  ok — blocked before reaching the model, with a redacted copy to resend"

echo "[2/3] reading a token-bearing file must reach the model redacted"
OUT2="$(claude -p "read ci-values.txt and tell me VERBATIM the exact value of CI_TOKEN" 2>&1)"
echo "$OUT2" | grep -q "$TOKEN" && { echo "FAIL: raw token crossed to the model/transcript"; exit 1; }
echo "$OUT2" | grep -q "SECRETGATE_" || { echo "WARN: no placeholder mentioned; inspect: $OUT2"; }
echo "  ok — raw token never crossed"

echo "[3/3] asking to copy the value must restore the REAL token on disk"
claude -p "read ci-values.txt, then create copy.env containing the same CI_TOKEN line" --permission-mode acceptEdits > /dev/null 2>&1
grep -q "CI_TOKEN=$TOKEN" copy.env || { echo "FAIL: copy.env does not contain the restored real token"; cat copy.env; exit 1; }
echo "  ok — placeholder restored to the real value on disk"

echo "ALL E2E SCENARIOS PASSED"
