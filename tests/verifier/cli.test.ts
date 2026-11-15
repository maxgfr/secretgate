import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { run } from "../../src/cli.js";
import { loadConfig } from "../../src/config.js";
import { ASSETS, assetDir } from "../../src/verifier/assets.js";

let home: string;
function capture() {
  const out: string[] = [];
  const err: string[] = [];
  return {
    io: { stdout: (s: string) => out.push(s), stderr: (s: string) => err.push(s), stdin: () => Promise.resolve("") },
    text: () => out.join(""),
    errText: () => err.join(""),
  };
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "secretgate-vcli-"));
  process.env.SECRETGATE_HOME = home;
});
afterEach(() => {
  delete process.env.SECRETGATE_HOME;
  rmSync(home, { recursive: true, force: true });
});

describe("secretgate verifier", () => {
  it("on and off write the verifier entry of config.json and keep the rest of the file, comments included", async () => {
    writeFileSync(join(home, "config.json"), '{\n  // my settings\n  "restoreBash": true,\n}\n');
    const on = capture();
    expect(await run(["verifier", "on", "--threshold", "f05"], on.io)).toBe(0);
    expect(on.text()).toContain("ON (threshold f05)");
    expect(on.text()).toContain("FAILED its pre-registered gate");
    expect(on.text()).toContain("verifier fetch");
    const text = readFileSync(join(home, "config.json"), "utf8");
    expect(text).toContain("// my settings");
    expect(loadConfig()).toMatchObject({ restoreBash: true, verifier: { enabled: true, threshold: "f05" } });
    expect(await run(["verifier", "off"], capture().io)).toBe(0);
    expect(loadConfig()).toMatchObject({ restoreBash: true, verifier: { enabled: false, threshold: "f05" } });
  });

  it("refuses an unknown threshold or subcommand, and a config.json it cannot parse", async () => {
    const bad = capture();
    expect(await run(["verifier", "on", "--threshold", "f3"], bad.io)).toBe(2);
    expect(await run(["verifier", "nope"], capture().io)).toBe(2);
    writeFileSync(join(home, "config.json"), "{ not json");
    const broken = capture();
    expect(await run(["verifier", "on"], broken.io)).toBe(2);
    expect(broken.errText()).toContain("nothing was written");
    expect(readFileSync(join(home, "config.json"), "utf8")).toBe("{ not json");
  });

  it("status says it is off, the assets are missing, and what it is", async () => {
    const c = capture();
    expect(await run(["verifier"], c.io)).toBe(0);
    expect(c.text()).toContain("config    off");
    expect(c.text()).toContain("MISSING");
    expect(c.text()).toContain("verifier fetch");
    expect(c.text()).toContain("BENCH.md#s6-secrets-verify-pico");
  });

  it("secretgate status: off, on with missing assets, on with files that are not the pinned ones", async () => {
    const off = capture();
    await run(["status"], off.io);
    expect(off.text()).toContain("verifier  off (experimental, opt-in");
    writeFileSync(join(home, "config.json"), JSON.stringify({ verifier: { enabled: true } }));
    const missing = capture();
    await run(["status"], missing.io);
    expect(missing.text()).toMatch(/verifier {2}ON \(threshold f1\) but SKIPPED: .*missing/);
    mkdirSync(assetDir(), { recursive: true });
    for (const a of ASSETS) writeFileSync(join(assetDir(), a.file), "x");
    const mismatch = capture();
    await run(["status"], mismatch.io);
    expect(mismatch.text()).toMatch(/SKIPPED: sky_web_bg\.wasm mismatch/);
    writeFileSync(join(home, "config.json"), JSON.stringify({ verifier: "yes" }));
    const invalid = capture();
    await run(["status"], invalid.io);
    expect(invalid.text()).toContain("is invalid (verifier must be an object) — the verifier is OFF");
  });
});
