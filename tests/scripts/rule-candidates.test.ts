import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  assignedName,
  type CandidateRecord,
  candidateRecords,
  candidatesOf,
  charClasses,
  type DroppedMatch,
  GENERATOR,
  GENERIC_KEYWORD,
  genericCandidates,
  maskAll,
  maskKnown,
  maskName,
  maskValue,
  readText,
  valueIndex,
  walkFiles,
} from "../../scripts/rule-candidates.mjs";
import { dedupeFindings, rulePatterns, scan, traceMatches } from "../../src/engine/scanner.js";
import { FAKE } from "../fixtures/fake-tokens.js";

// The candidate export is a dev tool (scripts/rule-candidates.mjs): it writes
// what the scanner knows about each finding, for a model that will judge them.

const engine = { scan, rulePatterns };
const key = "test-key";
const classes = (v: string) => v.replace(/[a-z]/g, "a").replace(/[A-Z]/g, "A").replace(/[0-9]/g, "0");

describe("maskValue", () => {
  it("keeps length and character classes and changes every letter and digit", () => {
    for (const value of [FAKE.githubPat, FAKE.awsKeyId, "Zx9!kLm2#Qw8rT5yU", FAKE.anthropicKey, "a", "9", ""]) {
      const masked = maskValue(value, key);
      expect(masked).toHaveLength(value.length);
      expect(classes(masked)).toBe(classes(value));
      for (let i = 0; i < value.length; i++) {
        if (/[A-Za-z0-9]/.test(value[i]!)) expect(masked[i], `${value} @${i}`).not.toBe(value[i]);
        else expect(masked[i]).toBe(value[i]);
      }
    }
  });

  it("masks letters and digits outside ASCII too, in their own script", () => {
    const value = "pässwörd-密码-Привет-٣";
    const masked = maskValue(value, key);
    expect(masked).toHaveLength(value.length);
    for (let i = 0; i < value.length; i++) {
      if (value[i] === "-") expect(masked[i]).toBe("-");
      else expect(masked[i], `@${i}`).not.toBe(value[i]);
    }
    expect(/\p{Script=Cyrillic}{6}/u.test(masked)).toBe(true);
    expect(/\p{Script=Han}{2}/u.test(masked)).toBe(true);
  });

  it("is stable for one key and differs with another", () => {
    expect(maskValue(FAKE.githubPat, key)).toBe(maskValue(FAKE.githubPat, key));
    expect(maskValue(FAKE.githubPat, key)).not.toBe(maskValue(FAKE.githubPat, "another-key"));
    expect(maskValue(FAKE.githubPat, key)).not.toBe(maskValue(FAKE.githubPat.replace("a", "b"), key).replace("b", "a"));
  });

  it("masks letters and digits outside the Basic Multilingual Plane, keeping the length", () => {
    const value = "a\u{1D4B3}\u{1D7D8}\u{1D4CD}\u{1F600}b";
    const masked = maskValue(value, key);
    expect(masked).toHaveLength(value.length);
    expect([...masked].map((c, i) => c === [...value][i])).toEqual([false, false, false, false, true, false]);
  });

  it("keeps of a name its credential keywords and its shape, nothing else", () => {
    expect(maskName("DB_PASSWORD", key)).toMatch(/^[A-Z]{2}_PASSWORD$/);
    expect(maskName("DB_PASSWORD", key)).not.toBe("DB_PASSWORD");
    expect(maskName("aws_secret_access_key", key)).toMatch(/^[a-z]{3}_secret_[a-z]{6}_key$/);
    expect(maskName("apiKeyV2", key)).toMatch(/^apiKey[A-Z]\d$/);
    const plain = maskName("DATABASE_URL", key);
    expect(plain).toMatch(/^[A-Z]{8}_[A-Z]{3}$/);
    expect([...plain].filter((c, i) => c !== "_" && c === "DATABASE_URL"[i])).toEqual([]);
  });

  it("counts character classes", () => {
    expect(charClasses("aB3-_x")).toEqual({ lower: 2, upper: 1, digit: 1, other: 2 });
  });
});

describe("assignedName", () => {
  const at = (text: string, value: string) => assignedName(text, text.indexOf(value));
  it("isolates the key or variable a value is assigned to", () => {
    expect(at(`aws_secret_key = "VALUE"`, "VALUE")).toBe("aws_secret_key");
    expect(at(`{"db": {"token": "VALUE"}}`, "VALUE")).toBe("token");
    expect(at(`  - API_KEY=VALUE`, "VALUE")).toBe("API_KEY");
    expect(at(`const apiToken: string = 'VALUE';`, "VALUE")).toBe("string");
    expect(at(`\tapiKey := "VALUE"`, "VALUE")).toBe("apiKey");
    expect(at(`Authorization: Bearer VALUE`, "VALUE")).toBe("Authorization");
    expect(at(`first = 1\nsecond: VALUE`, "VALUE")).toBe("second");
    expect(at(`DATABASE_URL=postgres://app:VALUE@db/main`, "VALUE")).toBe("DATABASE_URL");
    expect(at(`see https://svc:VALUE@host/x`, "VALUE")).toBeUndefined();
  });

  it("answers undefined when the value is not assigned", () => {
    expect(at(`some text before\nVALUE\nafter`, "VALUE")).toBeUndefined();
    expect(at(`run deploy VALUE now`, "VALUE")).toBeUndefined();
  });
});

describe("candidatesOf — rule findings", () => {
  const text = `# service\nGITHUB_TOKEN=${FAKE.githubPat}\nurl = "postgres://admin:Xk9mQ2vL7pR4tY6h@db:5432/prod"\n`;

  it("writes rule, offsets, line, name, match and groups; entropy is the real value's", () => {
    const [pat, url] = candidatesOf(text, engine, { raw: true });
    expect(pat).toMatchObject({ mode: "rule", rule: "github-pat", line: 2, name: "GITHUB_TOKEN", length: FAKE.githubPat.length, masked: false });
    expect(text.slice(pat!.start, pat!.end)).toBe(FAKE.githubPat);
    expect(pat!.entropy).toBeGreaterThan(4);
    expect(pat!.match).toEqual({ start: pat!.start, end: pat!.end });
    expect(url).toMatchObject({ rule: "url-credentials", line: 3 });
    // The whole match is the URL; the value is the password, a capture group.
    expect(text.slice(url!.match!.start, url!.match!.end)).toMatch(/^postgres:\/\/admin:.*prod"$/);
    expect(url!.name).toBe("url");
    expect(url!.groups).toContainEqual([url!.start, url!.end]);
  });

  it("masks by default: no value survives, in its own context or in a neighbour's", () => {
    const out = candidatesOf(text, engine, { maskKey: key, context: 400 });
    const dump = JSON.stringify(out);
    expect(dump).not.toContain(FAKE.githubPat);
    expect(dump).not.toContain("Xk9mQ2vL7pR4tY6h");
    // Shape is kept: the masked value stands where the real one stood.
    const [pat] = out;
    expect(pat!.context.before + pat!.context.value + pat!.context.after).toHaveLength(text.length);
    expect(classes(pat!.context.value)).toBe(classes(FAKE.githubPat));
    // Nothing of the context is readable but the keyword in the value's own name.
    expect(pat!.name).toMatch(/^[A-Z]{6}_TOKEN$/);
    expect(pat!.name).not.toBe("GITHUB_TOKEN");
    expect(pat!.context.before).toMatch(/^# [a-z]{7}\n[A-Z]{6}_TOKEN=$/);
    expect(pat!.context.before.endsWith(`${pat!.name}=`)).toBe(true);
    expect(dump).not.toContain("service");
    expect(dump).not.toContain("postgres");
  });

  it("masks a value everywhere the file repeats it, not only where a rule found it", () => {
    const repeated = `echo ${FAKE.githubPat} # then\nGITHUB_TOKEN=${FAKE.githubPat}\nexpect(out).toContain("${FAKE.githubPat.slice(0, 20)}");\n`;
    const out = candidatesOf(`run with password = "Xq9$mK2vLp7wRt4z" (yes: Xq9$mK2vLp7wRt4z)\n${repeated}`, engine, { maskKey: key, context: 400 });
    expect(JSON.stringify(out)).not.toContain(FAKE.githubPat);
    expect(JSON.stringify(out)).not.toContain("Xq9$mK2vLp7wRt4z");
  });

  it("masks a value another file holds, where no rule has the context to flag it", () => {
    // The generic value is a finding in config.toml only; notes.md repeats it bare.
    const known = valueIndex([FAKE.genericSecret, "short"]);
    const notes = `rotate ${FAKE.genericSecret} soon, see short note\nGITHUB_TOKEN=${FAKE.githubPat}\n`;
    // Masked with or without the index; with it, as the one value it is, so
    // that it reads the same in every file of the export.
    expect(JSON.stringify(candidatesOf(notes, engine, { maskKey: key, context: 400 }))).not.toContain(FAKE.genericSecret);
    const [pat] = candidatesOf(notes, engine, { maskKey: key, context: 400, known });
    expect(JSON.stringify(pat)).not.toContain(FAKE.genericSecret);
    expect(pat!.context.before).toContain(maskValue(FAKE.genericSecret, key));
    expect(pat!.context.before).not.toContain("short note");
    expect(maskKnown(`a ${FAKE.genericSecret} b ${FAKE.genericSecret}`, known, key)).toBe(
      `a ${maskValue(FAKE.genericSecret, key)} b ${maskValue(FAKE.genericSecret, key)}`,
    );
    expect(maskAll(`rotate ${FAKE.genericSecret} soon`, known, key)).toBe(
      `${maskValue("rotate", key)} ${maskValue(FAKE.genericSecret, key)} ${maskValue("soon", key)}`,
    );
    expect(maskAll("see short note 42", undefined, key)).toMatch(/^[a-z]{3} [a-z]{5} [a-z]{4} \d{2}$/);
  });

  it("bounds the context window", () => {
    const [pat] = candidatesOf(`${"x".repeat(500)} ${FAKE.githubPat} ${"y".repeat(500)}`, engine, { maskKey: key, context: 20 });
    expect(pat!.context.before).toHaveLength(20);
    expect(pat!.context.after).toHaveLength(20);
    expect(pat!.context.start).toBe(pat!.start - 20);
  });

  it("writes real values only when asked", () => {
    const [pat] = candidatesOf(text, engine, { raw: true });
    expect(pat!.context.value).toBe(FAKE.githubPat);
    expect(pat!.masked).toBe(false);
  });
});

describe("candidatesOf — generic candidates", () => {
  const text = [
    "DB_PASSWORD=Zx9!kLm2#Qw8rT5yU", // unquoted with punctuation: no rule proposes it
    "password: hunter2", // low entropy
    'secret = "correct horse battery staple"', // spaces
    "Authorization: Bearer abcdefghij0123456789abcdefghij",
    "const apiKey = process.env.API_KEY;", // code
    "password: string;", // a type
    "token = getToken()", // a call
    "retries = 3",
  ].join("\n");

  it("proposes credential-named assignments and auth headers the rules leave alone", () => {
    expect(scan(text)).toEqual([]);
    const found = genericCandidates(text).map((c) => [c.kind, c.name, text.slice(c.start, c.end)]);
    expect(found).toEqual([
      ["candidate:assignment", "DB_PASSWORD", "Zx9!kLm2#Qw8rT5yU"],
      ["candidate:assignment", "password", "hunter2"],
      ["candidate:assignment", "secret", "correct horse battery staple"],
      ["candidate:auth-header", "Authorization", "abcdefghij0123456789abcdefghij"],
    ]);
  });

  it("emits them only with `generic`, but masks them in every context", () => {
    const withRule = `${text}\nGITHUB_TOKEN=${FAKE.githubPat}\n`;
    const rulesOnly = candidatesOf(withRule, engine, { maskKey: key, context: 1000 });
    expect(rulesOnly.map((c) => c.rule)).toEqual(["github-pat"]);
    expect(JSON.stringify(rulesOnly)).not.toContain("hunter2");
    expect(JSON.stringify(rulesOnly)).not.toContain("correct horse");
    const all = candidatesOf(withRule, engine, { maskKey: key, generic: true });
    expect(all.map((c) => c.mode)).toEqual(["generic", "generic", "generic", "generic", "rule"]);
    expect(all[1]).toMatchObject({ rule: "candidate:assignment", name: "password", line: 2, length: 7 });
  });

  it("does not repeat what a rule already found", () => {
    const out = candidatesOf(`api_key = "${FAKE.genericSecret}"`, engine, { maskKey: key, generic: true });
    expect(out).toHaveLength(1);
    expect(out[0]!.mode).toBe("rule");
  });
});

describe("walkFiles / readText", () => {
  it("walks text files by extension, skipping .git, binaries and oversized files", () => {
    const dir = mkdtempSync(join(tmpdir(), "sg-candidates-"));
    try {
      mkdirSync(join(dir, ".git"));
      mkdirSync(join(dir, "src"));
      writeFileSync(join(dir, ".git", "config.json"), "{}");
      writeFileSync(join(dir, "src", "a.ts"), "export {};\n");
      writeFileSync(join(dir, "src", "b.bin"), "x");
      writeFileSync(join(dir, "notes.md"), "hello\n");
      writeFileSync(join(dir, "blob.json"), Buffer.from([1, 0, 2]));
      const rel = (files: string[]) => files.map((f) => f.slice(dir.length + 1));
      expect(rel([...walkFiles(dir)])).toEqual(["blob.json", "notes.md", "src/a.ts"]);
      expect(rel([...walkFiles(dir, { allText: true })])).toEqual(["blob.json", "notes.md", "src/a.ts", "src/b.bin"]);
      expect(readText(join(dir, "blob.json"))).toBeUndefined();
      expect(readText(join(dir, "notes.md"))).toBe("hello\n");
      expect(readText(join(dir, "notes.md"), 3)).toBeUndefined();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------- sg-cand-1

describe("generic-keyword", () => {
  const re = new RegExp(GENERIC_KEYWORD.re.source, GENERIC_KEYWORD.re.flags);
  // [name, value] of the first match in a line, or null.
  const parse = (line: string): [string, string] | null => {
    const m = re.exec(line);
    if (!m) return null;
    return [/^[\w.$-]+/.exec(m[0])![0], m.slice(1).find((v) => v !== undefined)!];
  };

  it("has the thirteen keywords, case-insensitive, anywhere in the name", () => {
    expect(GENERIC_KEYWORD.id).toBe("generic-keyword");
    expect(GENERIC_KEYWORD.keywords).toEqual([
      "password",
      "passwd",
      "pwd",
      "pass",
      "secret",
      "token",
      "key",
      "api",
      "auth",
      "credential",
      "cred",
      "nonce",
      "salt",
    ]);
    for (const k of GENERIC_KEYWORD.keywords) {
      expect(parse(`my_${k}_x = "abcd"`), k).toEqual([`my_${k}_x`, "abcd"]);
      expect(parse(`${k.toUpperCase()}=abcd`), k).toEqual([k.toUpperCase(), "abcd"]);
    }
    expect(parse(`$db.pass-word1 = 'abcd'`)).toEqual(["$db.pass-word1", "abcd"]);
    expect(parse("monkey = 1234")).toEqual(["monkey", "1234"]);
    expect(parse("retries = 1234")).toBeNull();
    expect(parse(`title = "abcd"`)).toBeNull();
  });

  it("takes each separator, with or without spaces and tabs around it", () => {
    for (const sep of [":", "=", ":=", "=>", "==", "!="]) {
      expect(parse(`token${sep}abcd`), sep).toEqual(["token", "abcd"]);
      expect(parse(`token \t${sep}  "abcd"`), sep).toEqual(["token", "abcd"]);
    }
    for (const line of ["token abcd", "token(abcd)", `token("abcd")`, "<token>abcd</token>", `"token", "abcd"`, "token -> abcd", "token <- abcd"])
      expect(parse(line), line).toBeNull();
  });

  it("takes an optional quote after the name and around the value", () => {
    expect(parse(`{"token": "abcd"}`)).toEqual(["token", "abcd"]);
    expect(parse(`'token' => 'abcd'`)).toEqual(["token", "abcd"]);
    expect(parse("`token` = `abcd`")).toEqual(["token", "abcd"]);
    // Nothing else may stand between the name and the separator.
    expect(parse(`config["token"] = "abcdefgh"`)).toBeNull();
    expect(parse(`\\"token\\": \\"abcdefgh\\"`)).toBeNull();
  });

  it("reads a quoted value up to its closing quote", () => {
    expect(parse(`secret = "ab cd, ef; gh"`)).toEqual(["secret", "ab cd, ef; gh"]);
    expect(parse(`secret = 'it is "quoted" here'`)).toEqual(["secret", `it is "quoted" here`]);
    // No closing quote on the line: not a quoted value, and a bare value
    // cannot begin with a quote.
    expect(parse(`secret = "abcdefgh`)).toBeNull();
    expect(parse(`secret = "abc" + "defgh"`)).toBeNull();
  });

  it("reads a bare value up to the first whitespace, semicolon, comma or line end", () => {
    expect(parse("token=abcd1234 next")).toEqual(["token", "abcd1234"]);
    expect(parse("token=abcd1234;next")).toEqual(["token", "abcd1234"]);
    expect(parse("token=abcd1234,next")).toEqual(["token", "abcd1234"]);
    expect(parse("token=abcd1234\nnext")).toEqual(["token", "abcd1234"]);
    expect(parse("token=abcd1234\r\nnext")).toEqual(["token", "abcd1234"]);
    expect(parse("token: Zx9!k(Lm2)#Q/w8+r=")).toEqual(["token", "Zx9!k(Lm2)#Q/w8+r="]);
  });

  it("wants 4 to 256 characters, quoted or bare", () => {
    expect(parse(`token = "abc"`)).toBeNull();
    expect(parse("token = abc")).toBeNull();
    expect(parse("token = abc, defgh")).toBeNull();
    expect(parse(`token = "${"a1".repeat(128)}"`)![1]).toHaveLength(256);
    expect(parse(`token = ${"a1".repeat(128)}`)![1]).toHaveLength(256);
    expect(parse(`token = "${"a1".repeat(128)}b"`)).toBeNull();
    expect(parse(`token = ${"a1".repeat(128)}b`)).toBeNull();
  });

  it("stays on one line", () => {
    expect(parse(`token =\n"abcdefgh"`)).toBeNull();
    expect(parse(`token\n= "abcdefgh"`)).toBeNull();
    expect(parse(`token = "abcd\nefgh"`)).toBeNull();
  });

  it("stays fast on a long run of name characters", () => {
    const blob = "keyapipwd".repeat(4000);
    const t0 = performance.now();
    expect(parse(`${blob} `)).toBeNull();
    expect(performance.now() - t0).toBeLessThan(5000);
  });
});

describe("candidateRecords (sg-cand-1)", () => {
  const trace = { scan, traceMatches, dedupeFindings };
  const raw = (text: string, opts: { sourcePath?: string; maxLine?: number; dropped?: DroppedMatch[] } = {}): CandidateRecord[] =>
    candidateRecords(text, trace, { raw: true, ...opts });
  const one = (text: string): CandidateRecord => {
    const out = raw(text);
    expect(out, text.slice(0, 40)).toHaveLength(1);
    return out[0]!;
  };
  const NONE = { entropy: false, placeholder: false, allowlist: false, stopword: false, context: false, pragma: false };

  it("writes the record of a value no default rule proposes", () => {
    const text = "# service\nDB_PASSWORD=Zx9!kLm2#Qw8rT5yU\nnext line\n";
    expect(scan(text)).toEqual([]);
    const [c, ...rest] = raw(text, { sourcePath: "conf/Service.ENV" });
    expect(rest).toEqual([]);
    expect(c).toEqual({
      generator: "sg-cand-1",
      file: "conf/Service.ENV",
      ext: ".env",
      rule: "generic-keyword",
      line: 2,
      start: 12,
      end: 29,
      cpStart: 12,
      cpEnd: 29,
      endLine: 2,
      offset: 22,
      length: 17,
      value: "Zx9!kLm2#Qw8rT5yU",
      name: "DB_PASSWORD",
      lineText: "DB_PASSWORD=Zx9!kLm2#Qw8rT5yU",
      lineFrom: 0,
      prevLine: "# service",
      nextLine: "next line",
      entropy: 4.0875,
      filters: NONE,
      reported: false,
      masked: false,
    });
    expect(GENERATOR).toBe("sg-cand-1");
    expect(c!.lineText.slice(c!.start, c!.end)).toBe(c!.value);
  });

  it("keeps what the default engine reports, and says so", () => {
    const text = `GITHUB_TOKEN=${FAKE.githubPat}\nurl = "postgres://admin:Xk9mQ2vL7pR4tY6h@db:5432/prod"\n${FAKE.privateKey}\ncard ${FAKE.visaPan}\n`;
    const found = scan(text, { sourcePath: "a.env" });
    expect(found.map((f) => f.ruleId)).toEqual(["github-pat", "url-credentials", "private-key", "credit-card-number"]);
    const out = raw(text, { sourcePath: "a.env" });
    expect(out.map((c) => [c.rule, c.offset, c.offset + c.length, c.reported, c.filters])).toEqual(found.map((f) => [f.ruleId, f.start, f.end, true, NONE]));
  });

  it("turns the filters off and records the one each value would have failed", () => {
    for (const [text, rule, filters] of [
      [`api_key = "aaaaaaaaaabbbbbbbbbb"`, "password-assignment", { ...NONE, entropy: true, placeholder: true }],
      [`passwd = "changeme"`, "password-assignment", { ...NONE, entropy: true, placeholder: true }],
      // The flags are those of the rule that names the candidate: this one has no entropy threshold.
      [`password = "changeme"`, "hashicorp-tf-password", { ...NONE, placeholder: true }],
      [`url = "postgres://app:changeme@db:5432/prod"`, "url-credentials", { ...NONE, placeholder: true }],
      [`api_key = ${FAKE.genericSecret.slice(0, 12)}example${FAKE.genericSecret.slice(12)}`, "generic-api-key", { ...NONE, stopword: true }],
      [`api_key = qzxjkvwqzjxkvwzqxjkv`, "generic-api-key", { ...NONE, entropy: true, allowlist: true }],
      [`cache_key = ${FAKE.genericSecret}`, "generic-api-key", { ...NONE, context: true }],
      [`token: ghp_${"a".repeat(8)}${FAKE.githubPat.slice(12)}`, "github-pat", { ...NONE, context: true }],
      [`key = ${FAKE.awsKeyId} # gitleaks:allow`, "aws-access-token", { ...NONE, pragma: true }],
      [`# pragma: allowlist nextline secret\nkey = ${FAKE.awsKeyId}`, "aws-access-token", { ...NONE, pragma: true }],
      // generic-keyword: no threshold and no list of its own, but the
      // filters that hold for every rule, and the name it trusts.
      [`pwd: hunter2`, "generic-keyword", { ...NONE, placeholder: true }],
      [`pwd: $HOME_DIR`, "generic-keyword", { ...NONE, placeholder: true, allowlist: true }],
      [`pwd: aaaa`, "generic-keyword", { ...NONE, placeholder: true, allowlist: true }],
      [`public_key: Zx9!kLm2#Qw8rT5yU`, "generic-keyword", { ...NONE, context: true }],
      [`pwd: Zx9!kLm2 # gitleaks:allow`, "generic-keyword", { ...NONE, pragma: true }],
    ] as const) {
      expect(scan(text), text).toEqual([]);
      const c = one(text);
      expect([c.rule, c.filters, c.reported], text).toEqual([rule, filters, false]);
    }
  });

  it("keeps the built-in rules' own gates and the engine's own material", () => {
    const dropped: DroppedMatch[] = [];
    const text = [
      `card ${FAKE.visaPanInvalid}`, // Luhn
      `url = "postgres://postgres:postgres@db:5432/prod"`, // the password repeats the username
      `password = "correct horse battery"`, // whitespace: not password-assignment's, still a keyword value
      `pwd = "/private/var/folders/pz/T/TestTmpDir/001"`, // a file path: the same
      `token = "SECRETGATE_0123456789abcdef"`, // already redacted
    ].join("\n");
    const out = raw(text, { dropped });
    expect(out.map((c) => [c.rule, c.line, c.value])).toEqual([
      ["generic-keyword", 3, "correct horse battery"],
      ["generic-keyword", 4, "/private/var/folders/pz/T/TestTmpDir/001"],
    ]);
    expect(dropped.map((d) => [d.rule, d.gate, d.line])).toEqual(
      expect.arrayContaining([
        ["credit-card-number", "post", 1],
        ["url-credentials", "post-match", 2],
        ["password-assignment", "post", 3],
        ["password-assignment", "post", 4],
        ["generic-keyword", "redacted", 5],
      ]),
    );
    // A dropped match is written without its value.
    expect(Object.keys(dropped[0]!).sort()).toEqual(["end", "endLine", "gate", "length", "line", "offset", "rule", "start"]);
    const card = dropped.find((d) => d.rule === "credit-card-number")!;
    expect(text.slice(card.offset, card.offset + card.length)).toBe(FAKE.visaPanInvalid);
  });

  it("ranks generic-keyword below every other rule in dedupe", () => {
    // The same value under a vendor rule, the generic rule and the keyword rule.
    expect(one(`token = "${FAKE.githubPat}"`)).toMatchObject({ rule: "github-pat", value: FAKE.githubPat, name: "token", reported: true });
    expect(one(`api_token = ${FAKE.genericSecret}`)).toMatchObject({ rule: "generic-api-key", value: FAKE.genericSecret, reported: true });
    expect(one(`password = "Zx9!kLm2#Qw8rT5yU"`)).toMatchObject({ rule: "password-assignment", value: "Zx9!kLm2#Qw8rT5yU", reported: true });
    // A few stray characters around the other rule's value: the narrower value.
    expect(one(`token = "${FAKE.githubPat}.."`)).toMatchObject({ rule: "github-pat", value: FAKE.githubPat });
    // More than that around it: the keyword rule's wider value is the candidate.
    const wide = `user ${FAKE.githubPat} and more`;
    expect(one(`auth = "${wide}"`)).toMatchObject({ rule: "generic-keyword", value: wide, name: "auth", reported: true });
  });

  it("covers every finding of the default engine", () => {
    const text = [
      `GITHUB_TOKEN=${FAKE.githubPat}`,
      `anthropic: ${FAKE.anthropicKey}`,
      `slack = "${FAKE.slackBotToken}"`,
      `api_key = "${FAKE.genericSecret}"`,
      `curl -X POST ${FAKE.discordWebhook} -d '{}'`,
      `GROQ=${FAKE.groqKey} R8=${FAKE.replicateToken}`,
      `card ${FAKE.visaPan}`,
      FAKE.privateKey,
    ].join("\n");
    const found = scan(text, { sourcePath: "notes.txt" });
    expect(found.length).toBeGreaterThanOrEqual(8);
    const out = raw(text, { sourcePath: "notes.txt" });
    for (const f of found)
      expect(
        out.some((c) => c.reported && c.offset <= f.start && c.offset + c.length >= f.end),
        f.ruleId,
      ).toBe(true);
  });

  it("gives no candidate under the global path allowlist, and passes the path to the engine", () => {
    const text = `GITHUB_TOKEN=${FAKE.githubPat}\npwd: Zx9!kLm2\n`;
    expect(raw(text, { sourcePath: "node_modules/pkg/index.js" })).toEqual([]);
    expect(raw(text, { sourcePath: "yarn.lock" })).toEqual([]);
    expect(raw(text, { sourcePath: "src/index.js" })).toHaveLength(2);
    expect(raw(text)[0]).toMatchObject({ file: null, ext: "" });
  });

  it("counts columns in UTF-16 units and in code points", () => {
    const c = one("😀😀 token=abcd1234 😀");
    expect([c.start, c.end, c.cpStart, c.cpEnd]).toEqual([11, 19, 9, 17]);
    expect(c.lineText.slice(c.start, c.end)).toBe("abcd1234");
    expect([...c.lineText].slice(c.cpStart, c.cpEnd).join("")).toBe("abcd1234");
  });

  it("places a value that spans lines, and strips line endings", () => {
    const [key] = raw(`before\r\n${FAKE.privateKey}\r\nafter\r\n`);
    expect(key).toMatchObject({
      rule: "private-key",
      line: 2,
      endLine: 4,
      start: 0,
      prevLine: "before",
      nextLine: "after",
      lineText: "-----BEGIN RSA PRIVATE KEY-----",
    });
    expect(key!.end).toBe("-----END RSA PRIVATE KEY-----".length);
    expect(key!.value).toBe(FAKE.privateKey);
    const c = one("a=1\r\ntoken=abcd1234\r\nb=2\r\n");
    expect(c).toMatchObject({ line: 2, value: "abcd1234", lineText: "token=abcd1234", prevLine: "a=1", nextLine: "b=2" });
    expect(one("token=abcd1234")).toMatchObject({ line: 1, prevLine: null, nextLine: null });
  });

  it("cuts a long line to a window around the value", () => {
    const text = `${"x".repeat(3000)} token=abcd1234 ${"y".repeat(3000)}\n${"z".repeat(500)}\n`;
    const [c] = raw(text, { maxLine: 100 });
    expect(c!.lineText).toHaveLength(100);
    expect(c!.lineFrom).toBeGreaterThan(2900);
    expect(c!.lineText.slice(c!.start - c!.lineFrom, c!.end - c!.lineFrom)).toBe("abcd1234");
    expect(c!.nextLine).toBe("z".repeat(100));
    expect(raw(text)[0]!.lineText).toHaveLength(1000);
    expect(raw(`token=abcd1234 ${"y".repeat(3000)}`, { maxLine: 100 })[0]).toMatchObject({ lineFrom: 0, start: 6 });
  });

  it("masks by default: the value, its line and its neighbours, kept as a candidate or not", () => {
    const text = [
      `url = "postgres://admin:admin@db:5432/prod"`, // dropped by a kept gate: still masked
      `DB_PASSWORD=Zx9!kLm2#Qw8rT5yU`,
      `echo Zx9!kLm2#Qw8rT5yU and ${FAKE.githubPat}`,
      `GITHUB_TOKEN=${FAKE.githubPat}`,
    ].join("\n");
    const out = candidateRecords(text, trace, { maskKey: key });
    expect(out.map((c) => c.rule)).toEqual(["generic-keyword", "github-pat", "github-pat"]);
    const dump = JSON.stringify(out);
    for (const secret of ["Zx9!kLm2#Qw8rT5yU", FAKE.githubPat, "admin"]) expect(dump).not.toContain(secret);
    const [pwd] = out;
    expect(pwd).toMatchObject({ masked: true, length: 17, entropy: 4.0875 });
    expect(pwd!.prevLine).toMatch(/^[a-z]{3} = "[a-z]{8}:\/\/[a-z]{5}:[a-z]{5}@[a-z]{2}:\d{4}\/[a-z]{4}"$/);
    expect(classes(pwd!.value)).toBe(classes("Zx9!kLm2#Qw8rT5yU"));
    // The name keeps its keyword and nothing else; the line shows the same name.
    expect(pwd!.name).toMatch(/^[A-Z]{2}_PASSWORD$/);
    expect(pwd!.name).not.toBe("DB_PASSWORD");
    expect(pwd!.lineText).toBe(`${pwd!.name}=${pwd!.value}`);
    expect(pwd!.nextLine).toBe(`${maskValue("echo", key)} ${pwd!.value} ${maskValue("and", key)} ${out[1]!.value}`);
    // A value another file holds is masked here too.
    const known = valueIndex(["elsewhere-value-1"]);
    const other = candidateRecords("token=abcd1234 # was elsewhere-value-1", trace, { maskKey: key, known });
    expect(other[0]!.lineText).not.toContain("elsewhere-value-1");
  });
});

// A masked export must not carry anything that could be a secret: a value no
// rule proposes often stands next to one a rule found.
describe("masked exports", () => {
  const trace = { scan, traceMatches, dedupeFindings };
  const awsSecret = "wJalrXUtnFEMI" + "K7MDENGbPxRfiCY" + "Zx9kLm2Qw8rT";
  const R = "Zx9!kLm2#Qw8" + "rT5yU";
  const reversed = [...R].reverse().join("");
  const INPUTS: Array<[string, string, string[]]> = [
    ["a credentials CSV", `Access key ID,Secret access key\n${FAKE.awsKeyId},${awsSecret}\nnext user,row 2\n`, [FAKE.awsKeyId, awsSecret]],
    ["a second secret on the command line", `aws configure set aws_access_key_id ${FAKE.awsKeyId} && export S=${awsSecret}\n`, [FAKE.awsKeyId, awsSecret]],
    ["a value copied in a comment, reversed", `pwd = "${R}" # backup copy ${reversed}\n`, [R, reversed]],
    ["short values and short repeats", `id 7Qz\ntoken = abcd1234 # pin 9Z1, id 7Qz, pin 9Z1\nuser bob\n`, ["abcd1234", "7Qz", "9Z1", "bob"]],
  ];
  const isWordChar = (c: string | undefined) => c !== undefined && /[\p{L}\p{N}]/u.test(c);
  // Positions where a letter or a digit of `raw` is still there in `masked`.
  const kept = (raw: string | null, masked: string | null): number[] => {
    if (raw === null || masked === null) {
      expect(masked).toBe(raw);
      return [];
    }
    expect(masked).toHaveLength(raw.length);
    return Array.from(raw, (_, i) => i).filter((i) => isWordChar(raw[i]) && masked[i] === raw[i]);
  };
  // Positions of the record's own name in a text that ends where the value starts.
  const namePositions = (before: string, name: string | null): Set<number> => {
    const at = name === null ? -1 : before.lastIndexOf(name);
    return new Set(name === null || at === -1 ? [] : [...name].map((_, i) => at + i));
  };

  for (const [what, text, secrets] of INPUTS) {
    it(`--candidates: ${what}`, () => {
      expect(awsSecret).toHaveLength(40);
      const raw = candidateRecords(text, trace, { raw: true });
      const masked = candidateRecords(text, trace, { maskKey: key });
      expect(raw.length).toBeGreaterThan(0);
      expect(masked).toHaveLength(raw.length);
      for (const secret of secrets) expect(JSON.stringify(masked), secret).not.toContain(secret);
      raw.forEach((r, i) => {
        const m = masked[i]!;
        expect(m.masked).toBe(true);
        expect(kept(r.value, m.value)).toEqual([]);
        expect(kept(r.prevLine, m.prevLine)).toEqual([]);
        expect(kept(r.nextLine, m.nextLine)).toEqual([]);
        // In its own line, only the keyword of the record's name may stay.
        const allowed = namePositions(r.lineText.slice(0, r.start - r.lineFrom), r.name);
        expect(kept(r.lineText, m.lineText).filter((p) => !allowed.has(p))).toEqual([]);
        expect(m.name).toBe(r.name === null ? null : maskName(r.name, key));
      });
    });

    for (const generic of [false, true]) {
      it(`${generic ? "--generic" : "default mode"}: ${what}`, () => {
        const raw = candidatesOf(text, engine, { raw: true, generic, context: 400 });
        const masked = candidatesOf(text, engine, { maskKey: key, generic, context: 400 });
        expect(masked).toHaveLength(raw.length);
        for (const secret of secrets) expect(JSON.stringify(masked), secret).not.toContain(secret);
        raw.forEach((r, i) => {
          const m = masked[i]!;
          expect(kept(r.context.value, m.context.value)).toEqual([]);
          expect(kept(r.context.after, m.context.after)).toEqual([]);
          const allowed = namePositions(r.context.before, r.name);
          expect(kept(r.context.before, m.context.before).filter((p) => !allowed.has(p))).toEqual([]);
          expect(m.name).toBe(r.name === null ? null : maskName(r.name, key));
        });
      });
    }
  }

  it("finds something to mask in each of them", () => {
    for (const [what, text] of INPUTS)
      expect(candidatesOf(text, engine, { raw: true, generic: true }).length + candidateRecords(text, trace, { raw: true }).length, what).toBeGreaterThan(0);
  });
});

// The command line imports the TypeScript engine through Node's type
// stripping, which the oldest Node of the test matrix does not have.
describe.skipIf(Number(process.versions.node.split(".")[0]) < 24)("rule-candidates.mjs --candidates", () => {
  it("scans a list of files below a base and writes records, dropped matches and counts", () => {
    const dir = mkdtempSync(join(tmpdir(), "sg-cand-"));
    try {
      mkdirSync(join(dir, "data", "repo", "src"), { recursive: true });
      writeFileSync(join(dir, "data", "repo", "src", "a.env"), `# service\nDB_PASSWORD=Zx9!kLm2#Qw8rT5yU\ncard ${FAKE.visaPanInvalid}\n`);
      writeFileSync(join(dir, "data", "repo", "src", "b.svg"), `token=abcd1234\n`);
      writeFileSync(join(dir, "data", "repo", "src", "c.bin"), Buffer.from([1, 0, 2]));
      writeFileSync(join(dir, "list.txt"), "repo/src/a.env\nrepo/src/b.svg\nrepo/src/c.bin\nrepo/src/missing.txt\n");
      const script = join(__dirname, "..", "..", "scripts", "rule-candidates.mjs");
      const run = (...more: string[]) =>
        spawnSync(
          process.execPath,
          [
            script,
            "--candidates",
            "--files-from",
            "list.txt",
            "--base",
            "data",
            "--out",
            "out.jsonl",
            "--dropped",
            "dropped.jsonl",
            "--stats",
            "stats.json",
            ...more,
          ],
          {
            cwd: dir,
            encoding: "utf8",
          },
        );
      const lines = (name: string) =>
        readFileSync(join(dir, name), "utf8")
          .split("\n")
          .filter((l) => l !== "")
          .map((l) => JSON.parse(l));

      // An output that already exists with wider permissions is closed down too.
      writeFileSync(join(dir, "out.jsonl"), "old\n");
      chmodSync(join(dir, "out.jsonl"), 0o644);
      const masked = run();
      expect(masked.status, masked.stderr).toBe(0);
      expect(statSync(join(dir, "out.jsonl")).mode & 0o777).toBe(0o600);
      expect(masked.stderr).toContain("values masked");
      expect(readFileSync(join(dir, "out.jsonl"), "utf8")).not.toContain("Zx9!kLm2#Qw8rT5yU");
      expect(lines("out.jsonl")).toMatchObject([
        { generator: "sg-cand-1", file: "repo/src/a.env", ext: ".env", rule: "generic-keyword", line: 2, masked: true },
      ]);

      const real = run("--raw");
      expect(real.status, real.stderr).toBe(0);
      expect(real.stderr).toContain("REAL values");
      expect(lines("out.jsonl")).toMatchObject([{ file: "repo/src/a.env", value: "Zx9!kLm2#Qw8rT5yU", masked: false }]);
      expect(lines("dropped.jsonl")).toEqual([
        { file: "repo/src/a.env", rule: "credit-card-number", gate: "post", line: 3, start: 5, end: 21, endLine: 3, offset: 45, length: 16 },
      ]);
      expect(JSON.parse(readFileSync(join(dir, "stats.json"), "utf8"))).toMatchObject({
        generator: "sg-cand-1",
        files: 4,
        read: 2,
        skipped: { missing: 1, empty: 0, large: 0, binary: 1 },
        pathAllowlisted: 1,
        lines: 4,
        filesWithCandidates: 1,
        candidates: 1,
        byRule: { "generic-keyword": 1 },
        droppedByKeptGate: { post: 1 },
        masked: false,
      });

      expect(run("--generic").status).toBe(2);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
