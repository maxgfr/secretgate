# s6-secrets-pico vs the rule engine

**Decision: not adopted.** secretgate does not ship the model, as an option or
otherwise. On the synthetic bench it was trained for, it beats the rules. On
real text with no secret, at p ≥ 0.9, it flags about one chunk of code or docs
in ten and six files in ten. At p ≥ 0.999 it still flags one chunk in
seventeen and half of the files. A firewall that fires on most of the files an
agent reads is a firewall people switch off.
The rule engine stays the only detector. This page records the measurement so
it can be repeated against a later model.

Measured on 2026-11-14 on an Apple M5 (macOS 27.2, Node v24.22.2). Every run
used `nice -n 19` in one process while a GPU training job ran on the same
machine, so the latencies are upper bounds for this machine, not a benchmark.
secretgate was at `ab9c9a3` and skycmd at `a72ec99`.

## What was measured

- **The model:** `s6-secrets-pico` (skycmd, Apache-2.0), 445,345 ternary
  parameters, 250,272 bytes. It reads a short text and answers four typed
  questions: is a usable secret exposed, which service issued it, what kind of
  value it is, and which line. It returns probabilities, never a character span.
  Only the first question is used for detection here.
- **The engine:** skycmd's `sky-web` crate built to WebAssembly
  (`sky_web_bg.wasm`, 1,158,454 bytes, Apache-2.0).
- **The rules:** secretgate's own scanner (`src/engine/scanner.ts`), called the
  way the hooks call it on tool output: no source path and no inline pragmas.
- **The union:** a text counts as flagged when the rules or the model flag it.

Both assets come from immutable Hugging Face commits and are checked by sha256.
The script refuses any other bytes.

| file | pinned URL | sha256 |
| --- | --- | --- |
| model | `https://huggingface.co/maxgfr/s6-secrets-pico/resolve/170428032aad2de3047e37429bec465f4b221858/s6-secrets-pico.gguf` | `1fa48c1530607d6a81ee64ad858aebfe4a49f9e5e88b1ac89eb63f2cc73a097a` |
| engine | `https://huggingface.co/spaces/maxgfr/s6-secrets-pico/resolve/0cff076be6b854072ea75d730fb8a25c236d7d6f/pkg/sky_web_bg.wasm` | `8a5ffc2cc2a071bfda276cb486a12c8ea575b72a4a59cdda1a4efbfe07dcd99b` |

The engine comes from the model's demo Space, not from `maxgfr.github.io/skycmd/pkg/`.
That GitHub Pages path is rebuilt in place: on the day of the run it already
served a different build.

The measurement never runs downloaded JavaScript. `scripts/sky-wasm.mjs` hosts
the engine itself. The WebAssembly module can only reach five functions the
host provides: an Error constructor, a string reader, a throw, a clock and a
table initialiser. The host refuses a module that asks for any other import.
On the first 200 bench records it returns the same probabilities as the
engine's own wasm-bindgen glue, with a largest absolute difference of 0 and the
same answer on all 200. Everything specific to this model (which file, which
questions, how text is fed) lives in `scripts/s6-secrets-pico.mjs`.

### How long text is fed to the model

The model was trained on texts of 2 to 7 lines. On its bench the median text
has 111 characters and the longest 283. Its state window holds 320 tokens, and
the engine drops every token past the window without any warning (skycmd
`crates/sky-infer/src/s2/prompt.rs`, `build_state`). A separate check used the
engine's own tokenizer (`SkyEngine.tokens` in its glue) on secretgate's
README, `package.json` and `scanner.ts` and on a Rust file. Their first 400
characters make 189 to 249 tokens, and their first 1,000 characters already
fill the window. A whole file handed to the model in one piece is therefore
judged on its first few hundred characters.

So text is cut into chunks of whole lines, with at most 7 lines and at most
300 characters per chunk. A line longer than that is cut into 300-character
pieces that overlap by 100, so a key of up to 100 characters always lies whole
in one piece. A text's score is the highest P(secret) of its chunks. Smaller
and larger chunks were tried too (see below), with the same outcome.

## Results

### 1. skycmd's `secret_bench`

This is the bench that favours the model: 1,996 synthetic texts (docker-compose,
toml, go, ini), made by the same generator as the model's training data
(`sky-data secret-jev`, seed 1234). The model never saw these four file types
in training, but it did learn the generator's formats, templates and class
shares. Of the texts, 1,010 expose a usable secret.

| detector | recall | precision | accuracy | TP | FP | FN | TN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| rules | 0.9772 | 0.7183 | 0.7946 | 987 | 387 | 23 | 599 |
| model, p ≥ 0.5 / 0.9 / 0.99 / 0.999 | 0.9980 | 1.0000 | 0.9990 | 1008 | 0 | 2 | 986 |
| union, any of those thresholds | 1.0000 | 0.7230 | 0.8061 | 1010 | 387 | 0 | 599 |

- **The bench's label is narrower than secretgate's policy.** The bench counts
  only a live, usable credential as positive. secretgate redacts test and
  sandbox keys too, by design. The rules' 387 "false positives" are 177 test
  keys, 156 publishable keys, 35 random values that are not credentials and 19
  placeholders.
- **Scored against "secret or test credential"** (1,187 positives): the rules
  reach recall 0.9806, precision 0.8472 and accuracy 0.8833. The model at p ≥ 0.5
  reaches recall 0.8492, precision 1.0000 and accuracy 0.9103.
- **The 23 rule misses are all live secrets** (kind "secret" in the bench).
  The union recovers all of them.

### 2. secretgate's own material

This set uses the 12 fake values of `tests/fixtures/fake-tokens.ts`. Each one
is placed in 7 contexts an agent shows: a `.env` line, JSON, YAML, a code
assignment, a shell export, a timestamped log line, and a bare line between
two words. The set also includes the two texts `tests/e2e/real-scenarios.mjs`
feeds the hooks. That makes 86 texts, of which the rules flag 77.

| model threshold | rule detections the model also flags | model-only detections |
| --- | ---: | ---: |
| 0.5 | 62 / 77 | 1 |
| 0.9 | 61 / 77 | 1 |
| 0.99 | 57 / 77 | 1 |
| 0.999 | 56 / 77 | 1 |

- **Rule detections the model misses at 0.9: 16 of 77.**
  - All 7 Luhn-valid card numbers. The model was not trained on card numbers:
    none of its service options is a card.
  - All 8 vendor tokens placed inside the timestamped log line, whose scores
    there fall to 0.0016 or below.
  - The Discord webhook URL on a bare line (p = 0.69).
- **The one model-only detection** is the generic 30-character random string
  alone on a line, with no key name. The rules leave such a string alone on
  purpose: with nothing naming it, it is indistinguishable from a hash or an
  identifier.
- **The 9 texts the rules do not flag** are that same string in two contexts
  and the Luhn-invalid card number in seven. Even at p ≥ 0.5 the model flags
  none of the invalid card numbers.
- **The `tests/fixtures/fp-corpus` fixtures**, which the rules must keep at zero
  findings: the model flags 3 of the 8 files at p ≥ 0.9. They are the base64
  image (12 of 13 chunks), the lockfile chunk (2 of 2, its integrity hashes) and
  the decimal coordinates (1 of 3).

### 3. False positives on real text with no secret

This is the out-of-distribution check, the one that decides. The corpus is
up to 400 files per root, drawn by a seeded shuffle, with these extensions:
`.ts .js .mjs .cjs .json .md .toml .yml .yaml .rs`. Files over 256 KB and
binary files are skipped, and at most the first 100 chunks of each file are
used. A file in which the rules find anything is left out (6 files), so every
model flag counts as a false positive. The corpus totals 719 files and 22,433
chunks. Rates are given at p ≥ 0.5 / 0.9 / 0.99 / 0.999.

| root | files | chunks | chunks flagged | files flagged |
| --- | ---: | ---: | --- | --- |
| secretgate `src/` | 36 | 1,231 | 6.4 % / 5.4 % / 4.0 % / 2.3 % | 66.7 % / 61.1 % / 52.8 % / 38.9 % |
| secretgate `tests/` | 39 | 1,260 | 13.7 % / 10.6 % / 8.4 % / 6.3 % | 84.6 % / 79.5 % / 76.9 % / 69.2 % |
| secretgate `README.md` | 1 | 100 | 8.0 % / 5.0 % / 2.0 % / 2.0 % | 1 of 1 at every threshold |
| `node_modules/.pnpm` (sample) | 395 | 6,673 | 12.8 % / 10.3 % / 7.1 % / 4.8 % | 44.8 % / 40.3 % / 36.5 % / 29.4 % |
| skycmd `crates/` | 227 | 11,726 | 12.2 % / 10.2 % / 8.0 % / 6.0 % | 89.4 % / 86.8 % / 82.8 % / 78.0 % |
| skycmd `docs/` | 21 | 1,443 | 25.1 % / 20.7 % / 16.5 % / 12.5 % | 95.2 % at every threshold |
| **total** | **719** | **22,433** | **12.9 % / 10.6 % / 8.1 % / 5.9 %** | **63.7 % / 59.8 % / 55.9 % / 49.4 %** |

- **The scores are not calibrated out of distribution.** Over all clean chunks,
  the median P(secret) is 0.00009, the 90th percentile is 0.93 and the 99th is
  0.99999. Raising the threshold therefore barely helps: at p ≥ 0.999, half of
  the clean files still raise at least one flag.
- **What the flagged chunks contain:** ordinary text. The flags at p ≥ 0.9, in
  a seeded random sample of 40 and among the 25 highest scores, hold:
  - Rust `use` lists and arithmetic;
  - TypeScript imports, comments and test setup code;
  - Markdown paragraphs in English and French, reference lists of URLs and
    badge links;
  - JSON configuration of golden test files;
  - a CLI usage string;
  - a WebSocket frame-masking loop.

  None of the 25 highest-scoring chunks, all at p = 1.0000 once rounded,
  holds a credential-shaped value.
- **A stricter rule does not help.** The rule asks two more questions per
  flagged chunk: p ≥ 0.9, the kind question answers "a live credential", and
  the service question does not answer "none". It still flags 10.6 % of the
  chunks (2,377) and 59.7 % of the files (429). On the bench it keeps the same
  recall (0.9980) and precision (1.0000).
- **The chunk size does not change the picture.** The same corpus was run
  again with other chunk sizes:

  | chunk size | files | chunks | chunks flagged (p ≥ 0.9 / 0.999) | files flagged (p ≥ 0.9 / 0.999) |
  | --- | ---: | ---: | --- | --- |
  | 3 lines, 120 characters | 718 | 38,011 | 9.1 % / 5.5 % | 68.0 % / 58.5 % |
  | 7 lines, 600 characters | 718 | 20,195 | 9.8 % / 5.2 % | 57.5 % / 46.0 % |

  These two runs happened a few minutes before the main one, and skycmd `docs/`
  gained a file in between.

### 4. Latency

| what | measured |
| --- | --- |
| rules on one chunk | median 0.033 ms, p95 0.057 ms |
| model on one chunk, warm (secret question only) | median 2.545 ms, p95 4.401 ms (24,544 decisions) |
| `src/engine/scanner.ts` (21,909 bytes, 492 lines, 92 chunks) | rules 3.6 ms; model 228.7 ms |
| engine compile + model load, in an already running process | 10.8 ms |
| built bundle as a Claude Code PostToolUse hook, clean output, rules only | median 30.3 ms, p95 31.3 ms (25 runs) |
| fresh process, sources through type stripping, rules only | 53.5 ms wall |
| the same, plus verifying, loading and asking the model once | 86.3 ms wall |

- **Process start.** In the fresh model process the rules finish 37.9 ms after
  start. Hashing both files ends at 38.6 ms, the engine is loaded at 49.3 ms and
  the first decision returns at 54.8 ms. The model therefore adds about 17 ms
  inside the process and 33 ms of wall time. That cost is paid before it reads
  any real output, on every hook process, and the clean hook itself takes 30 ms.
- **Against the scan budget.** The hooks give one event 5,000 ms and 2 MiB
  (`src/hooks/scan-budget.ts`). The figures below are arithmetic on the
  medians above. At 2.545 ms per chunk, the model alone would spend the whole
  5,000 ms on about 1,960 chunks. At `scanner.ts`'s density of 238 bytes per
  chunk, that is about 470 KB of text, less than a quarter of what one event
  may carry. Any integration would have needed a separate, much smaller budget.
  It would also have left most of a large output unread by the model.

### 5. What a later model would face

A planned next model scores one rule candidate in its context and returns
P(real secret), so the rule engine still finds the span. Its workload looks
nothing like chunk scanning. The census ran the rules alone over every file of
the same roots, without sampling, as the hooks scan tool output. It covered
8,821 files.

- **Findings are rare.** 17 files have any, 65 findings in all.
  - Findings per file with any: 1 (4 files), 2 (4), 3 (3), 4 (4), 12 (1) and 16 (1).
  - By rule: password-assignment 26, generic-api-key 15, github-pat 8,
    url-credentials 7, credit-card-number 4, github-app-token 4, private-key 1.
  - The rule scan of one file takes a median of 0.13 ms (p95 2.62 ms).
  - At the warm decision time above, judging the worst file's 16 candidates
    would take about 41 ms. Chunk-scanning one 22 KB file takes 229 ms.
- **None of the 65 is a real credential.** On inspection:
  - 25 are deliberate fakes in test fixtures, correct detections by design:
    secretgate's own `tests/` (23) and two synthetic fixtures in skycmd's
    secret generator.
  - The other 40, in 12 files, are false positives such a verifier would have
    to clear:
    - documentation examples: an example token passed to an auth helper in a
      README (12), an example header value in HTTP-mocking docs copied in
      three packages (12), base64 example credentials in a package README (3),
      a doc-comment example of an API token (2), and a placeholder test
      password in skycmd (1);
    - public material: TLS public-key pin fingerprints in Node's type
      definitions (3) and a release GPG key fingerprint list (3);
    - code: a variable whose name merely contains "Keys", matched as a value
      (4).
- **What the scanner already knows about each finding** at match time
  (`src/engine/scanner.ts`, inside `scan`):
  - the rule id, the full regex match, and every capture group with its
    offsets (the regexes carry the `d` flag);
  - the selected secret value and its span, its Shannon entropy, and its
    0-based line;
  - the line's text, and the whole scanned text, from which any bounded
    context window can be cut;
  - the source path when the caller passes one. `scan` does; the hooks do not
    pass one for tool output, although a Read event carries the file path in
    its input (on purpose: see section 6).

  The key name is not a separate field. For assignment-style rules it is the
  part of the match before the operator.

### 6. What was done about the rules afterwards

Measured the same day on the same files, with the rules as they stand after
the changes this section describes. The secretgate roots are a copy of the tree
at `b1c59f5`, so the files do not move with the work; skycmd's tree had grown
by two files since section 5 (8,823 files). At `b1c59f5` the script returns
section 5's figures on them: 65 findings in 17 files, recall 0.9772.

**Rule noise.** 35 of the 40 false positives were values that say themselves
they are not a usable secret, and a rule can read that without losing a
detection:

| class (section 5) | before | after | what the rule reads |
| --- | ---: | ---: | --- |
| example token passed to an auth helper | 12 | 0 | a GitHub token with one character eight times in a row |
| example header value, three copies | 12 | 0 | a value made only of placeholder words |
| placeholder test password in skycmd | 1 | 0 | the same |
| variable name matched as a value | 4 | 0 | the "value" repeats the name it is assigned to |
| TLS public-key pins | 3 | 0 | the value's own name says "public key" |
| release GPG key fingerprints | 3 | 0 | hex after a name that says "GPG key" |
| base64 example credentials | 3 | 3 | nothing: real `_auth` values look the same |
| doc-comment example of an API token | 2 | 2 | nothing: twelve letters and digits |
| **false positives** | **40** | **5** | |
| deliberate fakes in test fixtures | 25 | 24 | a Stripe publishable key in skycmd's generator is no longer flagged: it is public by design |
| **findings** | **65** | **29** | in 17, then 8 files |

By rule, the 29 are password-assignment 13, url-credentials 7,
credit-card-number 4, generic-api-key 4 and private-key 1. The five that remain
are the population a verifier has to judge; no rule separates them from real
values.

The same pass has rules for cases the bench holds and the census does not: a
Stripe publishable key (`pk_live_`, `pk_test_`), a value ending in `EXAMPLE` or
partly masked, a name that says "cache key" or "fingerprint". Together they
remove every bench false positive except the test keys:

| rules | recall | precision | accuracy | TP | FP | FN | TN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| before | 0.9772 | 0.7183 | 0.7946 | 987 | 387 | 23 | 599 |
| after | 0.9772 | 0.8479 | 0.8998 | 987 | 177 | 23 | 809 |

The 177 that remain are the test keys secretgate redacts on purpose. Against
"secret or test credential" the rules now reach recall 0.9806 and precision
1.0000. The 23 misses are the same 23 texts.

**The 23 bench secrets the rules miss** are not all secrets a rule should catch:

- 18 are AWS access key ids that AWS could not have issued. The generator draws
  their 16 characters from `A-Z0-9`; AWS uses base32 (`A-Z2-7`), and each of the
  18 holds a 0, 1, 8 or 9. The AWS rule rightly does not match them. The
  generic rule does not take over: 17 sit under a name ending in `key_id` or
  `KeyId`, which upstream allowlists as an identifier, and one has an entropy
  of 3.5 or less. A wider AWS pattern would catch them and nothing real. The generator
  is what to fix.
- 4 are 32 hexadecimal characters under `api_secret`, `mailgun_api_key` or
  `datadog_api_key`, with an entropy at or below the generic rule's 3.5. Hex
  cannot exceed 4.0, so part of every batch of random hex keys falls under
  that floor. A hex-aware floor would catch them; it would also flag more
  hashes sitting under a name with "key" in it, and that trade needs a larger
  corpus than this one to be measured.
- 1 is an `sk-proj-` key whose random body happens to spell "best", one of the
  1,446 stopwords upstream applies to the generic rule's values. A rule keyed
  on the `sk-proj-` prefix would catch it safely. The stopword list costs the
  generic rule a share of all long random values, by chance alone.

**Source path.** Passing a Read's file path to the engine was measured and not
done. With a path, the census drops from 65 findings to 26 (at `b1c59f5`): all
39 findings under `node_modules` disappear, because upstream's path allowlist
exempts that tree whole, with lockfiles, vendor trees and more. A path only
ever switches scanning off: the allowlists return no finding, and the four
path-scoped rules, which run everywhere when there is no path, stop running on
other files. And a path is what a repository or an agent arranges most easily:
a secret copied under `node_modules/` or into a file named
`package-lock.json` would reach the model unredacted. The same goes for the
user's own path globs, which lift the read denial and, as the README says, keep
output redaction. A test now pins that a read is redacted whatever its path.

**Candidate export.** `scripts/rule-candidates.mjs` writes one JSON line per
rule finding with what section 5 lists (rule, offsets of the value, of the
match and of every capture group, line, name, entropy, a bounded context
window, file). The export is masked by default: every letter and digit of the
value and of its context is replaced by another of the same class, and only the
credential keyword inside the value's own name stays readable. On
the census files it writes 29 candidates from 8 files. With `--generic` it adds
the values assigned to credential-sounding names and the values of
authorization-style headers that no rule proposes, whatever their entropy or
quoting: 1,209 candidates from 303 files, of which 1,147 assignments and 33
headers. A masked export keeps no letter or digit of the files it read, proposed
by a rule or not; `--raw` writes the real text and is for local use only.

## Limits

- **One model, one engine build, one main run** (plus the two chunk-size
  variants). The latencies were taken on a busy machine.
- **The clean corpus is small.** It holds two of the owner's repositories and
  a sample of one `node_modules`, all developer text. Prompts, shell output and
  logs were only covered through the fixtures of section 2. skycmd's `docs/` is
  a live tree that changed during the measurement.
- **The secret material is constructed.** Section 2 places fixture tokens in
  invented contexts, and the bench is synthetic. Nothing here measures recall
  on real leaked credentials.
- **The bench is not distributed** with secretgate. It is generated locally by
  skycmd and hashed below.
- **Nothing of the model or the engine is committed here.** Both are
  Apache-2.0. The scripts download nothing: the files are fetched by hand
  from the pinned URLs and checked against their hashes.

## Reproduce

The script needs Node 22.18 or later: it imports the TypeScript scanner through
type stripping. It also needs `pnpm install`. It reads only the paths it is
given, writes only `--out`, and runs the committed bundle as a hook inside a
temporary home that it removes afterwards.

```sh
mkdir -p /tmp/s6-assets
curl -fL -o /tmp/s6-assets/s6-secrets-pico.gguf \
  https://huggingface.co/maxgfr/s6-secrets-pico/resolve/170428032aad2de3047e37429bec465f4b221858/s6-secrets-pico.gguf
curl -fL -o /tmp/s6-assets/sky_web_bg.wasm \
  https://huggingface.co/spaces/maxgfr/s6-secrets-pico/resolve/0cff076be6b854072ea75d730fb8a25c236d7d6f/pkg/sky_web_bg.wasm
shasum -a 256 /tmp/s6-assets/*   # must match the table above; the script refuses other bytes

# skycmd checked out next to secretgate; its bench comes from `sky-data secret-jev`
# (seed 1234); the file used here hashes to
# 1c6975a51aca70d8227960b6e9a232c0e3d3c193fc05721d65d46d5be7053664.
# --parity runs the engine's own glue to check the host: a copy of sky_web.js
# from the same build (served beside the wasm on the Space, sha256
# 102bf816000461b971b7466b9b163fb8e27aae05c2ca59c14675767a9fbc2dd6). Leave it
# out to run no foreign JavaScript.
nice -n 19 node scripts/model-compare.mjs \
  --wasm /tmp/s6-assets/sky_web_bg.wasm --model /tmp/s6-assets/s6-secrets-pico.gguf \
  --bench ../skycmd/data/secrets/secret_bench.jsonl \
  --parity ../skycmd/site/public/pkg/sky_web.js \
  --clean src --clean tests --clean README.md --clean node_modules/.pnpm \
  --clean ../skycmd/crates --clean ../skycmd/docs \
  --census --out /tmp/s6-assets/report.json

# the two chunk-size variants of section 3
nice -n 19 node scripts/model-compare.mjs --wasm … --model … --no-material --fresh-runs 0 \
  --chunk-lines 3 --chunk-chars 120 --clean …   # then --chunk-lines 7 --chunk-chars 600
```

Section 6 uses the same command, with `--max-files 1 --no-material
--fresh-runs 0` to skip what it does not need, once from a copy of the tree at
`b1c59f5` (`git archive b1c59f5 | tar -x -C /tmp/sg-base`) and once from the
current tree, both over the copy's `src`, `tests` and `README.md`. The export:

```sh
nice -n 19 node scripts/rule-candidates.mjs src tests README.md node_modules/.pnpm \
  ../skycmd/crates ../skycmd/docs --out /tmp/candidates.jsonl   # add --generic for the wide mode
```

The script prints the numbers behind every table on this page. It writes them
to `--out` too, along with the flagged chunks it sampled and the place, rule,
length and entropy of every census finding (never the value). The
classification in section 5 comes from reading those lines by hand.
