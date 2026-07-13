import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { run } from "../src/cli.js";
import { FAKE } from "./fixtures/fake-tokens.js";

let home: string;
let work: string;

function capture(stdin = "") {
  const out: string[] = [];
  const err: string[] = [];
  return {
    io: {
      stdout: (s: string) => out.push(s),
      stderr: (s: string) => err.push(s),
      stdin: () => Promise.resolve(stdin),
    },
    text: () => out.join(""),
    errText: () => err.join(""),
  };
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "secretgate-home-"));
  work = mkdtempSync(join(tmpdir(), "secretgate-work-"));
  process.env.SECRETGATE_HOME = home;
});

afterEach(() => {
  delete process.env.SECRETGATE_HOME;
  rmSync(home, { recursive: true, force: true });
  rmSync(work, { recursive: true, force: true });
});

describe("secretgate scan", () => {
  it("scans a file, reports the rule WITHOUT printing the raw secret, exits 1", async () => {
    const file = join(work, "config.yaml");
    writeFileSync(file, `key: ${FAKE.awsKeyId}\n`);
    const { io, text } = capture();
    const code = await run(["scan", file], io);
    expect(code).toBe(1);
    expect(text()).toContain("aws-access-token");
    expect(text()).not.toContain(FAKE.awsKeyId);
  });

  it("exits 0 on a clean file", async () => {
    const file = join(work, "clean.txt");
    writeFileSync(file, "nothing sensitive\n");
    const { io } = capture();
    expect(await run(["scan", file], io)).toBe(0);
  });

  it("scans stdin with '-'", async () => {
    const { io, text } = capture(`token=${FAKE.githubPat}`);
    const code = await run(["scan", "-"], io);
    expect(code).toBe(1);
    expect(text()).toContain("github-pat");
  });

  it("emits machine-readable findings with --json (masked, hash prefix, no raw secret)", async () => {
    const { io, text } = capture(`token=${FAKE.githubPat}`);
    const code = await run(["scan", "-", "--json"], io);
    expect(code).toBe(1);
    const parsed = JSON.parse(text());
    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0].ruleId).toBe("github-pat");
    expect(parsed.findings[0].sha256).toMatch(/^[0-9a-f]{12}$/);
    expect(text()).not.toContain(FAKE.githubPat);
  });

  it("walks directories, honors --exclude and skips node_modules", async () => {
    mkdirSync(join(work, "src"));
    mkdirSync(join(work, "node_modules", "dep"), { recursive: true });
    mkdirSync(join(work, "vendored"));
    writeFileSync(join(work, "src", "app.ts"), `const k = "${FAKE.genericSecret}"; // token = above`);
    writeFileSync(join(work, "src", "leak.env"), `GITHUB_TOKEN=${FAKE.githubPat}\n`);
    writeFileSync(join(work, "node_modules", "dep", "index.js"), `token = "${FAKE.genericSecret}"`);
    writeFileSync(join(work, "vendored", "rules.toml"), `token = "${FAKE.genericSecret}"`);
    const { io, text } = capture();
    const code = await run(["scan", work, "--exclude", "vendored/**"], io);
    expect(code).toBe(1);
    expect(text()).toContain("leak.env");
    expect(text()).not.toContain("node_modules");
    expect(text()).not.toContain("vendored");
  });
});

describe("secretgate pipe", () => {
  it("redacts stdin to stdout and exits 0", async () => {
    const { io, text } = capture(`export TOKEN=${FAKE.githubPat}\necho done`);
    const code = await run(["pipe"], io);
    expect(code).toBe(0);
    expect(text()).not.toContain(FAKE.githubPat);
    expect(text()).toMatch(/SECRETGATE_[0-9a-f]{12,16}/);
    expect(text()).toContain("echo done");
  });

  it("passes clean input through byte-identical", async () => {
    const { io, text } = capture("clean line\n");
    expect(await run(["pipe"], io)).toBe(0);
    expect(text()).toBe("clean line\n");
  });
});

describe("secretgate allow + vault", () => {
  it("allow <value> suppresses that exact value in later scans", async () => {
    const first = capture(`key: ${FAKE.awsKeyId}`);
    expect(await run(["scan", "-"], first.io)).toBe(1);
    const allowRun = capture();
    expect(await run(["allow", FAKE.awsKeyId], allowRun.io)).toBe(0);
    const second = capture(`key: ${FAKE.awsKeyId}`);
    expect(await run(["scan", "-"], second.io)).toBe(0);
  });

  it("allow --rule disables a rule id", async () => {
    // bare token: only github-pat matches (no assignment context for generic-api-key)
    const before = capture(`${FAKE.githubPat}`);
    expect(await run(["scan", "-"], before.io)).toBe(1);
    const allowRun = capture();
    expect(await run(["allow", "--rule", "github-pat"], allowRun.io)).toBe(0);
    const scanRun = capture(`${FAKE.githubPat}`);
    expect(await run(["scan", "-"], scanRun.io)).toBe(0);
  });

  it("vault list shows placeholders and rules but never secrets; vault clear wipes", async () => {
    const pipeRun = capture(`t=${FAKE.githubPat}`);
    await run(["pipe"], pipeRun.io);
    const list = capture();
    expect(await run(["vault", "list"], list.io)).toBe(0);
    expect(list.text()).toContain("github-pat");
    expect(list.text()).toMatch(/SECRETGATE_[0-9a-f]{12,16}/);
    expect(list.text()).not.toContain(FAKE.githubPat);
    const clear = capture();
    expect(await run(["vault", "clear"], clear.io)).toBe(0);
    const list2 = capture();
    await run(["vault", "list"], list2.io);
    expect(list2.text()).not.toMatch(/SECRETGATE_[0-9a-f]{12,16}/);
  });
});
