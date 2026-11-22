# Encoded-secret detection (local experimental branch)

The shared scanner now checks single-layer Base64/Base64url, hex and percent-encoded candidates after ordinary rule scanning. Detection remains local and uses existing rules; encoded-looking text alone is not a finding.

Findings retain original offsets and original encoded values. Redaction replaces the entire encoded candidate, and vault restoration returns exactly that original representation. Findings optionally identify `encoding`; the detector rule ID is unchanged. Assignment names and quotes are preserved in a same-line context window of at most 256 characters on each side.

Limits: 16 KiB per candidate, 128 successfully decoded context-distinct candidates and 256 KiB decoded bytes per scan, plus the existing shared wall-clock deadline. Individual oversized candidates are not decoded. Aggregate/deadline exhaustion uses the existing hook fail-closed behavior. Invalid UTF-8 and binary control characters are rejected. Existing attachment exclusions apply. Only one encoding layer is decoded. Fragment reconstruction, arbitrary structured-language parsing, whitespace-wrapped Base64 and secrets crossing encoded/plain boundaries are not supported.

This is a local modified variant, not an upstream release. Global installations and published native-tool results are unchanged.

Local reproduction from the parent workspace:

```sh
node bench/run.mjs claude --tool secretgate --suite smoke --secretgate-bundle "$PWD/secretgate/scripts/secretgate.mjs"
```

Use the original preserved bundle to run a baseline with the same option. New reports live under `bench/results/`; do not pool these modified results with the published default-tool comparison.
