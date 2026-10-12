import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  commandLine,
  hookProgram,
  hookRuntime,
  pinSelf,
  pinnedBinaryPath,
  pinnedBundlePath,
  runningInvocation,
  type SelfContext,
  selfForm,
  selfInvocation,
  stableRuntime,
} from "../src/self.js";

let dir: string;
let home: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "secretgate-self-"));
  home = join(dir, "home");
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

// A Bun --compile binary, as Homebrew installs it: modules in the virtual
// /$bunfs, process.execPath = the program in the Cellar.
function binaryContext(content = "binary v1"): SelfContext {
  const execPath = join(dir, "Cellar", "secretgate");
  mkdirSync(join(dir, "Cellar"), { recursive: true });
  writeFileSync(execPath, content, { mode: 0o755 });
  return { modulePath: "/$bunfs/root/secretgate-bin", execPath, home };
}

describe("selfForm", () => {
  it("tells the compiled binary, the Node bundle and the sources apart", () => {
    expect(selfForm("/$bunfs/root/secretgate-bin")).toBe("binary");
    expect(selfForm("B:\\~BUN\\root\\secretgate-bin.exe")).toBe("binary");
    expect(selfForm("/home/u/.secretgate/bin/secretgate.mjs")).toBe("bundle");
    expect(selfForm("/repo/src/self.ts")).toBe("dev");
  });
});

describe("pinSelf / selfInvocation — binary form", () => {
  it("pins a copy of the binary and wires it with no node in front", () => {
    const pinned = pinSelf(binaryContext());
    const target = pinnedBinaryPath(home);
    expect(pinned).toEqual({ file: target, args: [] });
    expect(commandLine(pinned)).toBe(`"${target}"`);
    expect(readFileSync(target, "utf8")).toBe("binary v1");
    expect(statSync(target).mode & 0o777).toBe(0o755);
    expect(readdirSync(join(home, "bin"))).toEqual(["secretgate"]); // no temp file left behind
  });

  it("refreshes the pinned copy on re-install (brew upgrade, then init)", () => {
    pinSelf(binaryContext("binary v1"));
    pinSelf(binaryContext("binary v2"));
    expect(readFileSync(pinnedBinaryPath(home), "utf8")).toBe("binary v2");
  });

  it("does not copy onto itself when the pinned binary runs init", () => {
    const target = pinnedBinaryPath(home);
    mkdirSync(join(home, "bin"), { recursive: true });
    writeFileSync(target, "binary v1", { mode: 0o755 });
    const ctx: SelfContext = { modulePath: "/$bunfs/root/secretgate-bin", execPath: target, home };
    expect(pinSelf(ctx)).toEqual({ file: target, args: [] });
    expect(readFileSync(target, "utf8")).toBe("binary v1");
  });

  it("self-tests run the pinned binary once it exists, the running one before", () => {
    const ctx = binaryContext();
    expect(selfInvocation(ctx)).toEqual({ file: ctx.execPath, args: [] });
    pinSelf(ctx);
    expect(selfInvocation(ctx)).toEqual({ file: pinnedBinaryPath(home), args: [] });
  });
});

describe("pinSelf / selfInvocation — bundle form", () => {
  it("pins the .mjs and runs it through the absolute node that installed it", () => {
    const bundle = join(dir, "secretgate.mjs");
    writeFileSync(bundle, 'const VERSION = "1.0.0";');
    const ctx: SelfContext = { modulePath: bundle, execPath: "/usr/bin/node", home };
    expect(selfInvocation(ctx)).toEqual({ file: "/usr/bin/node", args: [bundle] });
    const pinned = pinSelf(ctx);
    // A GUI-launched agent may not have nvm's node on its PATH: no bare `node`.
    expect(commandLine(pinned)).toBe(`"/usr/bin/node" "${pinnedBundlePath(home)}"`);
    expect(readFileSync(pinnedBundlePath(home), "utf8")).toBe('const VERSION = "1.0.0";');
    expect(existsSync(pinnedBinaryPath(home))).toBe(false);
    expect(selfInvocation(ctx)).toEqual({ file: "/usr/bin/node", args: [pinnedBundlePath(home)] });
  });
});

describe("runningInvocation", () => {
  it("runs this program, never an older pinned copy (OpenCode's plugin check)", () => {
    mkdirSync(join(home, "bin"), { recursive: true });
    writeFileSync(pinnedBinaryPath(home), "binary v0", { mode: 0o755 });
    writeFileSync(pinnedBundlePath(home), 'const VERSION = "0.0.1";');
    const bin = binaryContext();
    expect(runningInvocation(bin)).toEqual({ file: bin.execPath, args: [] });
    const bundle = join(dir, "secretgate.mjs");
    expect(runningInvocation({ modulePath: bundle, execPath: "/usr/bin/node", home })).toEqual({ file: "/usr/bin/node", args: [bundle] });
  });
});

describe("hookProgram", () => {
  it("finds the program a wired hook command runs", () => {
    expect(hookProgram('"/h/.secretgate/bin/secretgate" hook claude-code pre-tool-use')).toBe("/h/.secretgate/bin/secretgate");
    expect(hookProgram('node "/h/.secretgate/bin/secretgate.mjs" hook codex post-tool-use')).toBe("/h/.secretgate/bin/secretgate.mjs");
    expect(hookProgram("node /h/secretgate.mjs hook codex post-tool-use")).toBe("/h/secretgate.mjs");
    expect(hookProgram("secretgate hook claude-code user-prompt-submit")).toBe("secretgate");
    expect(hookProgram('"/opt/node/bin/node" "/h/.secretgate/bin/secretgate.mjs" hook codex post-tool-use')).toBe("/h/.secretgate/bin/secretgate.mjs");
  });

  it("names the runtime a wired hook command runs, when it has one", () => {
    expect(hookRuntime('"/opt/node/bin/node" "/h/secretgate.mjs" hook codex post-tool-use')).toBe("/opt/node/bin/node");
    expect(hookRuntime('node "/h/secretgate.mjs" hook codex post-tool-use')).toBe("node");
    expect(hookRuntime('"/h/.secretgate/bin/secretgate" hook claude-code pre-tool-use')).toBeUndefined();
  });
});

describe("stableRuntime", () => {
  it("names node by the PATH entry that survives upgrades, not the versioned binary it resolves to", () => {
    const cellar = join(dir, "Cellar", "node", "26.1.0", "bin");
    const bin = join(dir, "bin");
    mkdirSync(cellar, { recursive: true });
    mkdirSync(bin);
    writeFileSync(join(cellar, "node"), "", { mode: 0o755 });
    symlinkSync(join(cellar, "node"), join(bin, "node"));
    // A per-shell link (fnm's multishell dir) first on PATH is skipped: it dies with the shell.
    const shell = join(dir, "fnm_multishells", "123", "bin");
    mkdirSync(shell, { recursive: true });
    symlinkSync(join(cellar, "node"), join(shell, "node"));
    expect(stableRuntime(join(cellar, "node"), `/nowhere:${shell}:${bin}`, [bin])).toBe(join(bin, "node"));
    // No stable PATH entry leads to it: the binary itself.
    expect(stableRuntime(join(cellar, "node"), `/nowhere:${shell}`, [bin])).toBe(join(cellar, "node"));
  });
});
