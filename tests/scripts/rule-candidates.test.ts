import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  assignedName,
  candidatesOf,
  charClasses,
  genericCandidates,
  maskKnown,
  maskValue,
  readText,
  valueIndex,
  walkFiles,
} from "../../scripts/rule-candidates.mjs";
import { rulePatterns, scan } from "../../src/engine/scanner.js";
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
    const [pat, url] = candidatesOf(text, engine, { maskKey: key });
    expect(pat).toMatchObject({ mode: "rule", rule: "github-pat", line: 2, name: "GITHUB_TOKEN", length: FAKE.githubPat.length, masked: true });
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
    expect(pat!.context.before).toBe("# service\nGITHUB_TOKEN=");
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
    expect(JSON.stringify(candidatesOf(notes, engine, { maskKey: key, context: 400 }))).toContain(FAKE.genericSecret);
    const out = JSON.stringify(candidatesOf(notes, engine, { maskKey: key, context: 400, known }));
    expect(out).not.toContain(FAKE.genericSecret);
    expect(out).toContain("see short note");
    expect(maskKnown(`a ${FAKE.genericSecret} b ${FAKE.genericSecret}`, known, key)).toBe(
      `a ${maskValue(FAKE.genericSecret, key)} b ${maskValue(FAKE.genericSecret, key)}`,
    );
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
