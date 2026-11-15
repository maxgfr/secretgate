# Frozen engine of the generator `sg-cand-1`

These six files are the engine of secretgate commit `4e93cfa` (branch
`chore/sg-cand-1`), copied **byte for byte** from `src/engine/`: the engine the
candidate generator `sg-cand-1` ran when the verifier model
`s6-secrets-verify-pico` was trained and measured. The verifier option
(`src/verifier/`) generates its candidates with this copy, never with the default
engine in `src/engine/`, so that the rules, gates and dedupe the model was
measured with do not move when the default engine does.

Do not edit, format or lint them (`biome.json` leaves them out), and do not
regenerate `rules.gen.ts` here: `tests/verifier/generator.test.ts` pins each
file to its git blob id at `4e93cfa`.

| file | git blob at `4e93cfa` | sha256 |
|---|---|---|
| `allowlist.ts` | `583135a1102c8fad70884e41d1402c959b1d6cea` | `d6358bd96f04d20bab13f667823305c7a7a9543394fd501f4f9a97a17f0121f4` |
| `entropy.ts` | `5b02309fa59fd61635507043848ac41f8703f5a6` | `9c3b51742d6d290b458997e60ff5c790722ce1be4a322c01a3ac687129030eba` |
| `luhn.ts` | `a6a7d4aee86b4bf87dc838cbf7204fcd3b4c6e06` | `f9ae7dccdd177a01fd3d5041207a1441e182dffa192101d2f9bfe4ccbcbb7f54` |
| `pragma.ts` | `350c90f1239d90521fb70d9b59a96b58d95c4e3c` | `d948ac9a925080fa356196f3e85ff6b00a33d1b9885fc4b38edd4ab7fba20cb7` |
| `rules.gen.ts` | `a8cc8c106ec6d6e2587cb1e6c72c660994d9ecc5` | `b92a83d5819c3f99fd81bc961b1da5c31482c70e414f473783eb01a4c0908c5c` |
| `scanner.ts` | `e7b8f99da99cf64fb91ead34350b1da52034ca09` | `1551d424fcb499eeeb29523f432913264d34edd21fcf5709e4b5779b5ec1a31d` |

`rules.gen.ts` was generated from `rules/gitleaks.toml` with sha256
`e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf`. The sha256 of
`rules.gen.ts` and `scanner.ts` are the ones the frozen run recorded
(`run.json` of the s6-secrets v2 data).

Two comments of `scanner.ts` describe it as it stood in that commit: "For
development tools only (scripts/rule-candidates.mjs): the product does not call
anything below" was true of `src/engine/scanner.ts` there; in this copy the
verifier calls `traceMatches` and `dedupeFindings`. And "there is no deadline":
there is none here either. The verifier runs this engine in a child process
that is killed at a hard deadline (`../child.ts`), which no regex can outlast.
