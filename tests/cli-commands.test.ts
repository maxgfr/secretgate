import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { run } from "../src/cli.js";
import { disableState, recordSession } from "../src/disable.js";
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
  delete process.env.SECRETGATE_DISABLE;
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

  // Framework build output is regenerated on every build and is gitignored, but
  // it is full of generated key material — a Next.js `.next/` alone accounted
  // for 9 of the 42 findings on a scan of five local projects. `dist` and
  // `coverage` were already skipped; these are the same category.
  it("skips framework build output directories", async () => {
    mkdirSync(join(work, ".next", "cache"), { recursive: true });
    mkdirSync(join(work, "src"));
    writeFileSync(join(work, ".next", "cache", "manifest.json"), `{"encryptionKey":"${FAKE.genericSecret}"}`);
    writeFileSync(join(work, "src", "ok.ts"), "export const x = 1;\n");
    const { io, text } = capture();
    const code = await run(["scan", work], io);
    expect(code).toBe(0);
    expect(text()).not.toContain(".next");
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

describe("secretgate disable + enable", () => {
  const origCwd = process.cwd();

  afterEach(() => {
    process.chdir(origCwd);
  });

  it("with no session seen here, pauses the DIRECTORY for the default hour", async () => {
    process.chdir(work);
    const { io, text } = capture();
    expect(await run(["disable"], io)).toBe(0);
    expect(text()).toContain("DISABLED for directory");
    expect(text()).toContain("secretgate enable --project");
    // says what stopped protecting, and what did not
    expect(text()).toContain("no longer scanned");
    expect(text()).toContain("restore still runs");
    const state = disableState({ cwd: work });
    expect(state.disabled).toBe(true);
    expect(Date.parse(state.until!) - Date.now()).toBeGreaterThan(50 * 60_000);
  });

  it("pauses the agent run that is live in this directory, not the directory", async () => {
    process.chdir(work);
    recordSession("run-42", work);
    const { io, text } = capture();
    expect(await run(["disable"], io)).toBe(0);
    expect(text()).toContain("DISABLED for session run-42");
    expect(disableState({ cwd: work, sessionId: "run-42" }).disabled).toBe(true);
    // a different run in the same directory keeps its firewall
    expect(disableState({ cwd: work, sessionId: "other" }).disabled).toBe(false);
  });

  it("--project pauses the directory tree, --forever drops the expiry", async () => {
    process.chdir(work);
    recordSession("run-42", work);
    const { io } = capture();
    expect(await run(["disable", "--project", "--forever"], io)).toBe(0);
    const state = disableState({ cwd: join(work, "nested") });
    expect(state).toMatchObject({ scope: "path", disabled: true });
    expect(state.until).toBeUndefined();
  });

  it("--minutes is honored and capped at 24 h", async () => {
    process.chdir(work);
    const short = capture();
    await run(["disable", "--minutes", "5"], short.io);
    expect(Date.parse(disableState({ cwd: work }).until!) - Date.now()).toBeLessThan(6 * 60_000);
    const long = capture();
    await run(["disable", "--minutes", "100000"], long.io);
    expect(Date.parse(disableState({ cwd: work }).until!) - Date.now()).toBeLessThanOrEqual(1440 * 60_000 + 5_000);
  });

  it("rejects bad flags instead of half-disabling", async () => {
    const cases = [
      ["disable", "--minutes", "abc"],
      ["disable", "--minutes"],
      ["disable", "--session"],
      ["disable", "--project", "--session", "x"],
      ["disable", "--nope"],
    ];
    for (const argv of cases) {
      const { io } = capture();
      expect(await run(argv, io), argv.join(" ")).toBe(2);
    }
    expect(disableState({ cwd: work, sessionId: "x" }).disabled).toBe(false);
  });

  it("enable undoes disable, whichever scope it used", async () => {
    process.chdir(work);
    await run(["disable"], capture().io);
    const on = capture();
    expect(await run(["enable"], on.io)).toBe(0);
    expect(on.text()).toContain("re-enabled for directory");
    expect(disableState({ cwd: work }).disabled).toBe(false);

    recordSession("run-42", work);
    await run(["disable"], capture().io);
    const on2 = capture();
    await run(["enable"], on2.io);
    expect(on2.text()).toContain("re-enabled for session run-42");
    expect(disableState({ cwd: work, sessionId: "run-42" }).disabled).toBe(false);
  });

  it("enable --all clears every pause and says how many", async () => {
    process.chdir(work);
    await run(["disable", "--session", "a"], capture().io);
    await run(["disable", "--project"], capture().io);
    const { io, text } = capture();
    expect(await run(["enable", "--all"], io)).toBe(0);
    expect(text()).toContain("2 pause(s) cleared");
    expect(disableState({ cwd: work, sessionId: "a" }).disabled).toBe(false);
  });

  it("enable on an already-protected directory says so and points at what is still off", async () => {
    process.chdir(work);
    await run(["disable", "--session", "elsewhere"], capture().io);
    const { io, text } = capture();
    expect(await run(["enable"], io)).toBe(0);
    expect(text()).toContain("already protected");
    expect(text()).toContain("session elsewhere is still paused");
  });

  // No file can undo an env var — saying "re-enabled" without warning would be a lie.
  it("enable warns that SECRETGATE_DISABLE overrides it", async () => {
    process.chdir(work);
    process.env.SECRETGATE_DISABLE = "1";
    const { io, errText } = capture();
    await run(["enable"], io);
    expect(errText()).toContain("SECRETGATE_DISABLE is set");
  });

  it("keeps the store 0600 and never writes into the project directory", async () => {
    process.chdir(work);
    await run(["disable"], capture().io);
    const store = JSON.parse(readFileSync(join(home, "disabled.json"), "utf8"));
    expect(store.version).toBe(1);
    expect(() => readFileSync(join(work, ".secretgate.json"), "utf8")).toThrow();
  });

  // scan/pipe are explicit invocations: the user asking for a scan IS the intent.
  it("does not disable `scan` or `pipe`", async () => {
    process.chdir(work);
    process.env.SECRETGATE_DISABLE = "1";
    const scanRun = capture(`key: ${FAKE.awsKeyId}`);
    expect(await run(["scan", "-"], scanRun.io)).toBe(1);
    const pipeRun = capture(`token=${FAKE.githubPat}`);
    await run(["pipe"], pipeRun.io);
    expect(pipeRun.text()).not.toContain(FAKE.githubPat);
  });
});

describe("secretgate status", () => {
  const origHome = process.env.HOME;
  const origCwd = process.cwd();

  afterEach(() => {
    if (origHome === undefined) delete process.env.HOME;
    else process.env.HOME = origHome;
    process.chdir(origCwd);
  });

  it("leads with a DISABLED banner — wired-but-off must never read as protected", async () => {
    process.env.HOME = home;
    process.chdir(work);
    await run(["disable", "--project"], capture().io);
    const { io, text } = capture();
    expect(await run(["status"], io)).toBe(0);
    const lines = text().split("\n");
    expect(lines.findIndex((l) => l.includes("DISABLED"))).toBeLessThan(lines.findIndex((l) => l.includes("claude-code")));
    expect(text()).toContain("secretgate enable");
  });

  it("names the env var when that is what is off", async () => {
    process.env.HOME = home;
    process.chdir(work);
    process.env.SECRETGATE_DISABLE = "1";
    const { io, text } = capture();
    await run(["status"], io);
    expect(text()).toContain("unset SECRETGATE_DISABLE");
  });

  it("lists pauses that apply elsewhere, so a forgotten one is still visible", async () => {
    process.env.HOME = home;
    process.chdir(work);
    await run(["disable", "--session", "elsewhere"], capture().io);
    const { io, text } = capture();
    await run(["status"], io);
    expect(text()).toContain("also paused: session elsewhere");
  });

  it("says nothing about disabling when nothing is disabled", async () => {
    process.env.HOME = home;
    process.chdir(work);
    const { io, text } = capture();
    await run(["status"], io);
    expect(text()).not.toContain("DISABLED");
    expect(text()).not.toContain("also paused");
  });

  it("reports global and project claude-code scopes from a project directory", async () => {
    process.env.HOME = home;
    process.chdir(work);
    const { io, text } = capture();
    expect(await run(["status"], io)).toBe(0);
    expect(text()).toContain("claude-code global");
    expect(text()).toContain("claude-code project");
  });

  it("does not report a duplicate project scope when cwd IS the home directory", async () => {
    process.env.HOME = home;
    process.chdir(home);
    const { io, text } = capture();
    expect(await run(["status"], io)).toBe(0);
    expect(text()).toContain("claude-code global");
    expect(text()).not.toContain("claude-code project");
  });
});
