# The experimental verifier (opt-in)

secretgate can run a small model after its rules: the **verifier**. It is
**off by default**, it never downloads anything on its own, and it can only add
redactions to what the rules already do. It makes a hook slower: by a bounded
amount, given below. This page says what it is, what it
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
| clean real files with an accepted candidate (8,825 files), **with the file's path** | **0.35%** (31 files) | default rules 0.12% |
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
accepts more on the clean files (below). **The rates that apply to the hooks
are the option's own, measured at the end of this page: 0.46% of the clean files
get a verifier redaction without a path (Bash output), 0.27% with it (Read).**

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

To silence it for one value, `secretgate allow <value>` works as for a rule.
`secretgate allow --rule <rule id>` reaches the verifier too: a rule you
disabled proposes no candidate to it (a value only that rule proposes is not
judged; one another rule also proposes still is, under that rule). `secretgate
allow --rule verifier:s6-secrets` switches the verifier off entirely.

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

- The rules' pass over the whole event runs first and is complete, exactly as
  with the option off. The verifier then works from the original text and
  judges only the candidates that **no** rule finding overlaps; a rule finding
  is redacted exactly as without it (same span, same placeholder, same rule
  id): the measurements below check this file by file.
- What it may add: the values it accepts, **at their own span only**, the span
  the candidate generator reported. A value it accepts is never looked for
  elsewhere: another occurrence of it in the event (an echo in a log line, a
  path segment, a longer token that holds it, an object key) stays as the
  rules left it. The model's precision was about 0.84: a false acceptance must
  stay one wrong redaction, never spread through the text (an accepted
  `postgres` must not eat `postgresql://` or `postgres_fdw`, an accepted
  `node_modules` must not touch `node_modules2`). An earlier version redacted
  other whole-token occurrences of a long, unusual accepted value; it was
  removed after review, because it rewrote ordinary text.
- It judges and rewrites string **values** only: object keys of a tool result
  (`filePath`, `stdout`, `type`…) are never sent to it nor rewritten by it; the
  rules redact keys as they always did. A span it answers is applied only if it
  lies in its text, splits no surrogate pair, and is not inside or across an
  existing placeholder (one that holds a whole placeholder is kept: the
  restore resolves the nested one).
- With the option **off**, nothing changed: `tests/e2e/option-off.mjs` runs the
  bundles of v1.8.1 and of this version on the same 59 recorded hook events and
  commands (every event of Claude Code, Codex and the OpenCode plugin; scan,
  pipe, vault list, status) and finds no difference in stdout, stderr, exit
  codes or files written, but the new `status` line, the new `--help` line and
  the new command.
- Every failure skips it, and the hook answers with the rules' result exactly
  as with the option off: the data files missing or not the pinned ones, a
  WebAssembly error on load or on a candidate, the child process killed at its
  bound, crashing or answering garbage, a `verifier` entry in config.json that
  is not understood. It never makes a hook fail closed, never blocks an agent.

## Budget: a hard bound

A hook is a fresh process, and the generator's frozen `generic-keyword` regex is
quadratic on text an attacker can write (40 KB of `keykeykey…` take 0.4 s; a
Read of `key` ×5,000, `=`, 1,030,000 spaces kept a hook busy for 29.5 s in the
first version of this option). No deadline can interrupt one regex, and an
estimate cannot be the safety of a regex that may not change. So:

- **The generator and the model run in a child process** of the same program
  (`secretgate __verifier-job`: the Node bundle under the same node, or the
  Homebrew binary itself), and the hook **kills it (SIGKILL) at 1,000 ms** from
  its start. When it has not answered by then, there is nothing to add: the
  hook answers with the rules' result. A child process starts in about 30 ms
  (Node bundle) or 15 ms (Bun binary) here; a worker thread starts faster
  (about 10 ms and 4 ms), but Bun did not interrupt a worker stuck in a regex
  (it waited for the regex), and a worker shares the hook's memory, where a
  process killed with its own memory takes a runaway allocation with it.
- **Everything the verifier causes after its child answers** (re-redacting
  the strings it adds to) runs under **one deadline per event, 250 ms** from
  that answer. Each distinct string is handled once (an output that repeats a
  string pays once), the cheapest rule pass first; a string whose rules' pass
  took longer than the time left is not redacted again; and past the deadline
  the strings left keep the rules' result. `tests/hooks/verifier-review4.test.ts`
  checks this on a clock the test drives, so that the machine's load does not
  decide it: past the deadline, the output is byte for byte the option-off one.
- So the **worst-case added wall time per hook event is 1,000 ms for the child
  plus 250 ms after it, about 1.25 s** (a rule that is running when the deadline
  passes finishes first: the rules' deadline is checked between two rules),
  against the 30 s hook timeout. On the review's input (one value, then 20
  identical 100 KB strings that end with it), the first version of this bound
  added 4.5 s (7.0 s on, 2.5 s off); now -0.28 to +0.57 s over three paired runs
  of the bundle with the real model.
  Tests prove it on the reviewer's inputs and on other quadratic shapes (long
  names, many separators, escaped quotes, a 1 MiB line whose keyword comes at
  the end, 2 MiB of keywords), through `PostToolUse` (Read and Bash) and
  `PostToolBatch`, with the early skip below turned off, so that the kill alone
  holds the bound, and with children that loop, grow their memory, ignore
  SIGTERM, crash or answer garbage (`tests/hooks/verifier-bound.test.ts`; with
  `SECRETGATE_BOUND_STRICT=1` the child's time must stay within 150 ms of the
  bound, which it did in every case). A machine starved of CPU can fire any
  timer late; the bound is wall-clock time.
- Inside the child, a softer budget: **750 ms** from its start and **200
  candidates**, past which the candidates left are **not judged**
  (`SECRETGATE_DEBUG=verifier` says how many), so that it can answer with what
  it judged before the kill. Strings over **1 MiB**, and strings whose
  estimated cost for `generic-keyword` is too high, are skipped early: an early
  skip only, the kill is the bound.
- `PostToolBatch` reads every result again. The strings `PostToolUse` answered
  with are recorded by their sha256 (per session, in
  `~/.secretgate/verifier-batch/`, outside the asset directory; a session id
  that is not a plain name of letters, digits, `_` and `-` records nothing, so
  `.` or `..` can never name a path; taken by the batch) and not
  judged again when the batch carries them as they were answered. With Claude
  Code 2.1.325 it does not: the batch carries each result in the shape the
  model reads, so its strings are judged again, which costs one more child
  process per batch (43 to 56 ms in the live test) under the same hard bound;
  a result `PostToolUse` redacted holds no candidate any more there.
  A record not written to for **24 hours** (a session that ended before its
  batch, a take that crashed) is deleted the next time a hook touches that
  directory: at most 128 entries are looked at per hook, only files and links
  with a record's name, by their own time; a link is unlinked, never
  followed, and nothing is done when the directory is itself a link.
- Strings are walked in a fixed order and candidates are judged in text order.
  The engine is loaded only when a string has a candidate to judge, and the
  verifier's code is loaded only when it is on.

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
Read of the file (its path below the repository goes to the model). **These are
the rates that apply to the hooks**; the 0.35% of the model's evaluation was
measured with the file's path given to the model, and with the model alone.

| | Bash output, no path | Read, with the path |
|---|---:|---:|
| files with a verifier redaction | **41 (0.46%)** | **24 (0.27%)** |
| values the verifier accepted | 85 | 61 |
| candidates / left to a rule finding | 13,475 / 80 | 13,475 / 80 |
| candidates judged / not judged (child budget or cap reached, files) | 12,242 / 1,153 (6 files) | 11,927 / 1,468 (11 files) |
| files where the child hit the **hard bound** (killed, nothing added) | **0** | **0** |
| child process time, spawn to answer, median / p95 / max | 42 / 122 / 809 ms | 55 / 171 / 997 ms |
| hook wall time off → on, median | 38.8 → 84.3 ms | 47.8 → 112.9 ms |
| **added wall time per file, median / p95** | **44 / 127 ms** | **59 / 187 ms** |
| added wall time per file, max | 863 ms | 3,258 ms (a load spike: see below) |
| files where the rules' output changed | **0** | **0** |
| hook failures, off / on | 0 / 0 | 0 / 0 |

This census was run with the earlier version that also redacted other
whole-token occurrences of an accepted value (30 more places in 5 files
without a path, 24 in 4 files with it); that step is gone, and it was not run
again. The counts above are those of the accepted values themselves, which
the removal does not change; the added times include the few strings that
step redacted again.

"The rules' output changed" is checked file by file: with every placeholder of
the verifier put back to its value, the output with the verifier on must be the
output with it off, byte for byte (same rule findings, same placeholders). The
median added time is mostly the child process's start (it runs for every event
with text, before anyone knows whether it holds a candidate).

The maxima of a census are not bounds on this machine: it was shared with a
training job, and a fresh process can wait seconds for the CPU. The Read
reading's maximum (3,258 ms) came with a child that answered in under 1 s; a
second full run put other files on top (up to 5,057 ms, children of 43 to
494 ms), and those five files, replayed four times each, added at most 460 ms.
The bound itself is what `tests/hooks/verifier-bound.test.ts` measures.

These files are clean: every redaction above is a false positive of the
verifier, as far as they were read. skycmd's hand reading of the 110 candidates
the model accepts with the path found none that looks like a real credential;
16 of them are provider-format values listed in the `gcp-api-key` allowlist of
the rule file secretgate ships, and 7 an example GitHub token of a library's
README, both of which the default engine's filters drop. The candidates it
accepts only without a path were not read by hand.

### secretgate's own fixtures

The same measurement on this repository's `tests/fixtures/` (12 files) and
`tests/` (62 files), whose fake tokens are mostly assembled by concatenation:

| | `tests/fixtures`, no path | `tests/fixtures`, Read | `tests`, no path | `tests`, Read |
|---|---:|---:|---:|---:|
| candidates / left to a rule / judged | 58 / 2 / 56 | 58 / 2 / 56 | 547 / 69 / 478 | 547 / 69 / 478 |
| values accepted (files redacted) | 1 (1) | 2 (1) | 6 (6) | 6 (5) |
| files where the rules' output changed | 0 | 0 | 0 | 0 |
| hook failures; hard-bound kills | 0; 0 | 0; 0 | 0; 0 | 0; 0 |
| added wall time per file, median / p95 | 119 / 205 ms | 100 / 193 ms | 120 / 269 ms | 125 / 231 ms |

The verifier never fights the rules there: it judges only what no rule found,
and no rule finding changed.

### Other costs

- Per candidate (the end-to-end proof, 4,234 candidates): median 2.68 ms and
  p95 5.53 ms with the relaxed-SIMD build, median 3.73 ms and p95 7.47 ms with
  the SIMD128 build (on a less loaded moment of the same machine; under the
  heaviest load of the re-run, 3.48 and 5.22 ms).
- With the verifier **off**: its code is not loaded, but the bundle is larger
  (`scripts/secretgate.mjs` 389,863 → 590,656 bytes; the OpenCode plugin
  275,115 → 277,172), and a hook starts about 1 ms later (median 45.0 → 46.0
  ms over 120 interleaved runs of a small PostToolUse event). Its answers are
  those of v1.8.1 (`tests/e2e/option-off.mjs`).
- The Homebrew binary (Bun) runs the same child (itself, `__verifier-job`) and
  loads the relaxed-SIMD build; with the option off and no data file it behaves
  as before (`pnpm run smoke:binary`).
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
  time the verifier loads it. No hook ever touches the network.
- **Symlinks and permissions: accepted, by decision.** v1.8.1 follows a
  settings symlink only to a file that can be a settings file, because what it
  reads there is trusted as policy. Here nothing is trusted from the file but
  its bytes: each file is read once, checked against its pin, and compiled from
  that same buffer, so a symlink, a file other accounts can write, or two files
  swapped can only fail their pin, and the verifier is then skipped (the rules
  are not concerned). A path that is not a regular file (a directory, a
  dangling link) counts as missing, and a file of the wrong size is refused
  unread.
- **Vendored**, reviewed source in this repository, never downloaded: the
  WebAssembly host (`src/verifier/host.ts`, from `verify-host.mjs` sha256
  `7190b42f…0ac0ce` at the same commit; it refuses a module that asks for any
  import but its five), and the frozen engine and generator.
- **Sandbox**: the WebAssembly module's only reach out of its sandbox is the
  five imports the host provides (an Error constructor, a string reader, a
  throw, a clock, a table initialiser). The bundle and the Homebrew binary
  contain the code, not the data files.
