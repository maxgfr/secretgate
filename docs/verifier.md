# The experimental verifier (opt-in)

secretgate can run a small model after its rules: the **verifier**. It is
**off by default**, it never downloads anything on its own, and it can only add
redactions to what the rules already do. This page says what it is, what it
measured, what it does in each hook, and what it costs.

## What it is, plainly

The verifier is the model **`s6-secrets-verify-pico`** from
[skycmd](https://github.com/maxgfr/skycmd): a 250 KB ternary model. A rule
proposes a candidate value; the model answers P(real credential) for that
candidate in its context; the candidate is accepted when P is at least a
threshold stored in the model file (`tau_f1` 0.2598 by default, also `tau_f05`
0.4684 and `tau_f2` 0.0781).

**It failed its pre-registered gate.** It had to beat the best rule scanner by
0.15 of line F1 over all the test repositories and reached +0.123. It is
published as a result, not as a validated detector. The system "rules or
verifier" (a line flagged by secretgate's default engine of that commit, or by
the verifier at a threshold of its own, 0.3493) was read too and failed the
same gate (line F1 0.8477 where 0.8832 was asked). The full result,
with every number below and the conditions they were measured under:
[skycmd BENCH.md, section "s6-secrets-verify-pico"](https://github.com/maxgfr/skycmd/blob/main/BENCH.md#s6-secrets-verify-pico-s6-secrets-v2-a-verifier-of-rule-candidates-pre-registered-gate-failed).

What was measured there, and nothing more is claimed here:

| | the verifier | for comparison |
|---|---|---|
| line F1 on 221 real test repositories (Samsung CredData) | **0.856** (precision 0.839, recall 0.874) | secretgate's default rules 0.728; the best rule scanner (Betterleaks) 0.733; an open 17M-parameter model (cbx-secrets-detector-17M) 0.683 |
| candidate F1 on issue reports with real values | **0.816** | Gitleaks 0.710 |
| clean real files with an accepted candidate (8,825 files) | **0.35%** (31 files) | default rules 0.12% |
| calibration (ECE, CredData test candidates) | 0.007 | |
| time per candidate | about 1.6 ms natively, 2.6 ms in WebAssembly | |

Those numbers are for the model on the candidates of the frozen generator
(below), **with the file's path** given to the model: CredData's scope words on
the repositories, and the path below its repository on the clean files (the
generator ran without a path there, the model's state had it). The one reading
without any path is the issue reports. secretgate's option is not exactly the
measured system: it runs after **today's** default engine (not the engine of
the measurement), it only judges what that engine left, it has a time budget,
and the hooks have a path for a Read only. Without the path, the same model
accepts more on the clean files (below). The measurements of the option itself
are at the end of this page.

## Turning it on

```
secretgate verifier fetch                     # download the four data files (pinned, sha256-checked)
secretgate verifier on                        # threshold f1 (default); or --threshold f05 | f2
secretgate verifier                           # status: config, each file verified or not, which engine build loads
secretgate verifier off
```

`on` and `off` write `"verifier": { "enabled": true, "threshold": "f1" }` into
`~/.secretgate/config.json` (comments and other keys are kept). Only that user
file counts: a repository's `.secretgate.json` cannot switch the verifier on or
off. An agent that runs `secretgate verifier on`, `off` or `fetch` is asked
first (Claude Code) or refused (Codex, OpenCode), like `secretgate disable`.

`secretgate status` has one line for it:

```
verifier  off (experimental, opt-in: `secretgate verifier` for details)
verifier  ON (threshold f1) but SKIPPED: dictionary.txt missing — run `secretgate verifier fetch`; the rules run as without it
verifier  ON (experimental), threshold f1 (tau 0.2598), assets verified, engine relaxed-simd build — redacts what it accepts as verifier:s6-secrets
```

What a user then sees: a value the verifier accepts is replaced by a
`SECRETGATE_…` placeholder in the tool output, exactly like a rule finding; it
is restored when the agent writes it back to a file; `secretgate vault list`
shows it under the rule id **`verifier:s6-secrets`**. To see what the verifier
did in a hook, set `SECRETGATE_DEBUG=verifier`: each hook writes one line to
stderr with counts, times and, for each accepted candidate, its line, the rule
that proposed it and P — never a value.

To silence it for one value, `secretgate allow <value>` works as for a rule;
`secretgate allow --rule verifier:s6-secrets` switches it off entirely.

## What it does in each hook

| where | what the verifier does |
|---|---|
| Claude Code `PostToolUse` (output of a successful tool call) | judges the candidates no rule finding overlaps; **redacts** what it accepts |
| Codex `PostToolUse` | the same; Codex substitutes the redacted result (block-and-replace), as for a rule finding |
| Claude Code `PostToolBatch` (the last gate before the model request) | runs only when the rules found nothing; **reports** what it accepts in a `systemMessage`, and **never stops the turn or closes the session** |
| `UserPromptSubmit` | does not run: it **never blocks a prompt** |
| `PreToolUse`, placeholder restore | not involved (restore works on every placeholder, whoever made it) |
| OpenCode plugin, `secretgate scan`, `secretgate pipe` | not covered by this version |

### A failed tool call

Claude Code lets no hook rewrite the output of a **failed** call (a command that
exits non-zero, a tool error). When a **rule** finds a secret there, secretgate
stops the turn and closes the session, as before. When only the **verifier**
accepts something there, it cannot be redacted and the turn is **not** stopped:
the value reaches the model as the tool printed it, and secretgate says so in a
`systemMessage` ("It was NOT redacted. Check the value and rotate it if it is
real"). A model's judgement does not stop a turn: only a rule finding does.

## The rules stay the authority

- The verifier runs after the rules, on the original text, and judges only the
  candidates that **no** finding of the default engine overlaps. A rule finding
  is redacted exactly as without the verifier (same span, same placeholder,
  same rule id): the measurement below checks this file by file.
- Its time is not taken from the rules: the rules' deadline is moved by the
  time the verifier spent, so it can make a hook slower by its budget, never
  make the rules run out of theirs.
- Every failure skips it, and the text goes on exactly as the rules left it:
  the data files missing or not the pinned ones, a WebAssembly error on load or
  on a candidate, the budget running out, a `verifier` entry in config.json
  that is not understood. It never makes a hook fail closed, never blocks an
  agent.

## Budget

A hook is a fresh process. Loading the engine costs about 20 ms; each
candidate about 2.6 ms (3.3 ms without relaxed SIMD). Per hook event, the
verifier has:

- **750 ms** of wall-clock time, the engine's load included;
- **200 candidates** at most;
- strings of at most **1 MiB** (a longer one is not given to the generator).

Strings are walked in a fixed order and candidates are judged in text order.
When the budget or the cap is reached, the candidates left are **not judged**
(and so not redacted by it); `SECRETGATE_DEBUG=verifier` says how many. The
engine is loaded only when a string has a candidate to judge, and the
verifier's code is loaded only when it is on: with it off, a hook loads none of
it.

One rule of the generator, `generic-keyword`, is quadratic on some inputs (a
run of `keykeykey…`: 40 KB of it take 0.4 s); a string whose estimated cost for
that rule is too high is not given to the generator, and the generator stops
between two rules once the budget is spent.

## Paths

The model was trained with CredData's path scope words (`test`, `src`,
`conf`…). It was evaluated without any path on the issue reports only; on the
clean files its state had the file's path below its repository (checked below:
every one of the 14,756 states of that evaluation is the state with the path,
none is the state without). The hooks pass no source path to the rules for tool
output, and the verifier does the same with one exception: for a **Read**, the
file's path below its repository is given to the **model** (never to the rules
or to the generator). Any other tool, or a
file outside the repository, gets no path. A path never switches the verifier
or the rules off: the generator never sees it, so the path allowlist of the
rule set cannot drop a file's candidates.

## The same generator, the same inputs

The model was trained and measured on the candidates of the generator
`sg-cand-1` (revision 1), frozen at secretgate commit `4e93cfa`
(`scripts/rule-candidates.mjs --candidates`): every gitleaks-derived and
built-in rule of that commit, with the entropy gates, the placeholder test, the
stopwords, the allowlists and the pragmas turned off and recorded as flags,
plus the rules `generic-keyword` and `auth-scheme`, with that commit's dedupe.
`main` has moved since (filters changed, a rule added), so the option does not
use the default engine to make candidates:

- `src/verifier/sg-cand-1/` is the engine of `4e93cfa`, **byte for byte** (six
  files; `rules.gen.ts` was generated from the same `rules/gitleaks.toml`,
  sha256 `e163e53b…329caf`). A test pins each file to its git blob id at
  `4e93cfa`.
- `src/verifier/generator.ts` is a port of the frozen script's raw path.
- `src/verifier/host.ts` is the reviewed WebAssembly host published with the
  model (`verify-host.mjs`), ported to TypeScript.

**Proof 1, the generator.** `scripts/verifier-proof.mjs` runs the module over
the files of the CredData training and validation repositories, in the frozen
run's order, with its paths and limits, and hashes the raw export as it is made
(it is never written). The split guard of the frozen runner is kept: only the
116 training and validation repositories are listed, every path is checked
again, a test repository stops the run.

| split | records | sha256 of the export | frozen file |
|---|---:|---|---|
| training (100 repositories, 3,741 files) | 211,802 | `f1946d90…dec8b2` | **byte-identical** |
| validation (16 repositories, 452 files) | 4,234 | `15aa997c…0ad5` | **byte-identical** |

In CI, without the data, `tests/verifier/generator.test.ts` pins the export of
82 records over fixture texts to the frozen script's own output.

**Proof 2, end to end** (validation, 4,234 candidates). The same records through
the option's path: the pinned files checked again, the WebAssembly engine, the
threshold read from the model file, against the skycmd evaluation (its states,
its native per-candidate probabilities, its flags file). The evaluation stored
CredData's paths as scope directories; the proof passes those scope words, as
the evaluation read them.

| | relaxed-SIMD build (what Node 24 and the Bun binary load here) | SIMD128 build |
|---|---|---|
| state text identical to the evaluation's | 4,234 / 4,234 | 4,234 / 4,234 |
| accepted (P ≥ tau_f1) | 515 | 516 |
| the evaluation's scorer (flags file, P with 6 decimals) accepted | 515: **the same set** | 515: one more here |
| the native engine's full-precision P (dump) at P ≥ tau | 516: one fewer here | 516: **the same set** |
| largest \|P − native P\| | 2.6e-6 | 2.7e-6 |

The one candidate that moves lies within 7e-7 of tau: its native P is just
above tau, the evaluation's 6-decimal flags put it just below, and each build
falls on one side. Every other accepted candidate is the same in all readings.

**Proof 3, the clean files.** `scripts/verifier-proof.mjs --clean` does the same on the census corpus of
[docs/model-comparison.md](model-comparison.md), as the s6-secrets v2 data froze
it (8,825 files): the generator with no source path, as the evaluation ran it,
gives the evaluation's 14,756 candidates; with the file's path below its
repository, the state is the evaluation's for **14,756 of 14,756** (without a
path, for none), and the accepted set is **the same 110 candidates in 31
files** (largest gap to the flags file 8.3e-7). Without a path the same model
accepts **141 candidates in 51 files**.

## Measurements of the option

Measured on an Apple M5 with Node v24.22.2, every process at the lowest
priority while a training job used the machine: times are those of a loaded
machine, not of an idle one.

### The census corpus, as a hook pays it

`scripts/verifier-measure.mjs` hands each of the 8,825 files to the built hook
as the output of a tool call (`PostToolUse`), in a fresh process, once with the
verifier off and once on, and records the verifier's own debug line. Two
readings: as the stdout of a Bash call (no path, as most tool output), and as a
Read of the file (its path below the repository goes to the model).

| | Bash output, no path | Read, with the path |
|---|---:|---:|
| files with a verifier redaction | **41 (0.46%)** | **23 (0.26%)** |
| values the verifier redacted | 85 | 60 |
| by the rule that proposed them | generic-keyword 45, gcp-api-key 16, generic-api-key 11, github-pat 7, password-assignment 4, url-credentials 2 | generic-keyword 25, gcp-api-key 16, generic-api-key 8, github-pat 7, password-assignment 4 |
| candidates (in 2,159 files) / left to a rule finding | 13,475 / 80 | 13,475 / 80 |
| judged / not judged (budget or cap reached, files) | 12,229 / 1,166 (10 files) | 12,104 / 1,291 (13 files) |
| strings over 1 MiB, not given to the generator | 1 | 1 |
| files where the rules' output changed | **0** | **0** |
| hook failures, off / on | 0 / 0 | 0 / 0 |
| verifier time per file, median / p95 / max | 1.3 / 62 / 690 ms | 2.8 / 72 / 750 ms |
| the same, files where it loaded the engine (2,154) | 41.7 / 118 ms | 45.8 / 151 ms |
| engine load, median / p95 | 20.7 / 35.5 ms | 21.6 / 42.1 ms |
| hook wall time off → on, median | 35.6 → 42.2 ms | 39.2 → 46.1 ms |
| added wall time per file, median / p95 / max | **4.0 / 80.7 / 716 ms** | **5.1 / 94.8 / 872 ms** |

"The rules' output changed" is checked file by file: with every placeholder of
the verifier put back to its value, the output with the verifier on must be the
output with it off, byte for byte (same rule findings, same placeholders).

These files are clean: every redaction above is a false positive of the
verifier, as far as they were read. skycmd's hand reading of the 110 candidates
the model accepts with the path found none that looks like a real credential;
16 of them are provider-format values listed in the `gcp-api-key` allowlist of
the rule file secretgate ships, and 7 an example GitHub token of a library's
README, both of which the default engine's filters drop. The candidates it
accepts only without a path were not read by hand.

### secretgate's own fixtures

The same measurement on this repository's `tests/fixtures/` (12 files) and
`tests/` (59 files), whose fake tokens are mostly assembled by concatenation:

| | `tests/fixtures`, no path | `tests/fixtures`, Read | `tests`, no path | `tests`, Read |
|---|---:|---:|---:|---:|
| candidates / left to a rule / judged | 58 / 2 / 56 | 58 / 2 / 56 | 502 / 69 / 433 | 502 / 69 / 433 |
| values redacted (files) | 1 (1) | 2 (1) | 6 (6) | 6 (5) |
| files where the rules' output changed | 0 | 0 | 0 | 0 |
| hook failures | 0 | 0 | 0 | 0 |
| added wall time per file, median / p95 | 52 / 194 ms | 51 / 136 ms | 65 / 257 ms | 81 / 419 ms |

The verifier never fights the rules there: it judges only what no rule found,
and no rule finding changed.

### Other costs

- Per candidate (the end-to-end proof, 4,234 candidates): median 2.68 ms and
  p95 5.53 ms with the relaxed-SIMD build, median 3.73 ms and p95 7.47 ms with
  the SIMD128 build.
- With the verifier **off**: its code is not loaded, but the bundle is larger
  (`scripts/secretgate.mjs` 389,863 → 577,228 bytes; the OpenCode plugin
  275,115 → 277,211) and a hook starts about 0.9 ms later (median 30.7 → 31.6
  ms over 120 interleaved runs of a small PostToolUse event).
- The Homebrew binary (Bun) loads the relaxed-SIMD build too; with the option
  off and no data file it behaves as before (`pnpm run smoke:binary`).
- With a real Claude Code (2.1.325) against a loopback model
  (`SECRETGATE_VERIFIER_ASSETS=… node tests/e2e/live-agents.mjs claude-code`):
  a value only the verifier accepts never reached a model request after a
  Read, and was restored on disk by a Write; in a failed command's output it
  reached the model and the turn went on.

## Supply chain

- **Downloaded**, by `secretgate verifier fetch` only: four data files from
  `https://huggingface.co/maxgfr/s6-secrets-verify-pico/resolve/9d44c27848bc13ea6015aab13b019710070737a5/engine/`
  (a commit of a Hugging Face repository is immutable), into
  `~/.secretgate/verifier/s6-secrets-verify-pico-9d44c27848bc/`:

  | file | bytes | sha256 |
  |---|---:|---|
  | `sky_web_bg.wasm` (engine, SIMD128) | 1,222,078 | `2ccf6fe227e9a773a19701283f938bded6258be951d879b684da8f23b4f78311` |
  | `sky_web_relaxed_bg.wasm` (engine, relaxed SIMD) | 1,219,957 | `d09fc19362993dc90c7e3c1f2bfe18147060599397c6ee2a759c9f7d12b86236` |
  | `s6-secrets-verify-pico.gguf` (model) | 249,984 | `01e6db3fa71cc2c5563dea222c68e040d3994ee2abbb02b25491a51b8cb54f27` |
  | `dictionary.txt` (word list) | 1,706,770 | `83f3f32b0df5fc92418dac25b8d1317ec537c0d4c6405961c9c06f31159c21e9` |

- **Verified**: size and sha256 of each file before it is written (a file that
  does not match is refused and nothing is written for it), and again every
  time a hook loads it. No hook ever touches the network.
- **Vendored**, reviewed source in this repository, never downloaded: the
  WebAssembly host (`src/verifier/host.ts`, from `verify-host.mjs` sha256
  `7190b42f…0ac0ce` at the same commit; it refuses a module that asks for any
  import but its five), and the frozen engine and generator.
- **Sandbox**: the WebAssembly module's only reach out of its sandbox is the
  five imports the host provides (an Error constructor, a string reader, a
  throw, a clock, a table initialiser). The bundle and the Homebrew binary
  contain the code, not the data files.
