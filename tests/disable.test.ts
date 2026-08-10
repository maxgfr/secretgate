import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { activePauses, addPause, clearPauses, describeDisable, disableState, envDisabled, recordSession, removePause, sessionForCwd } from "../src/disable.js";

let home: string;
let work: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "secretgate-disable-"));
  work = mkdtempSync(join(tmpdir(), "secretgate-work-"));
  process.env.SECRETGATE_HOME = home;
});

afterEach(() => {
  delete process.env.SECRETGATE_HOME;
  delete process.env.SECRETGATE_DISABLE;
  rmSync(home, { recursive: true, force: true });
  rmSync(work, { recursive: true, force: true });
});

const disabledPath = () => join(home, "disabled.json");

describe("SECRETGATE_DISABLE env scope", () => {
  it("accepts the documented truthy spellings and nothing else", () => {
    for (const on of ["1", "true", "TRUE", "yes", "on", " on "]) {
      process.env.SECRETGATE_DISABLE = on;
      expect(envDisabled(), on).toBe(true);
    }
    for (const off of ["", "0", "false", "no", "off", "maybe"]) {
      process.env.SECRETGATE_DISABLE = off;
      expect(envDisabled(), off).toBe(false);
    }
    delete process.env.SECRETGATE_DISABLE;
    expect(envDisabled()).toBe(false);
  });

  it("wins over everything, needs no payload, and reports the env scope", () => {
    process.env.SECRETGATE_DISABLE = "1";
    expect(disableState()).toEqual({ disabled: true, scope: "env" });
    expect(disableState({ cwd: work, sessionId: "s1" }).scope).toBe("env");
  });
});

describe("session and directory pauses", () => {
  it("is enabled by default — no store, nothing disabled", () => {
    expect(disableState({ cwd: work, sessionId: "s1" }).disabled).toBe(false);
    expect(activePauses()).toEqual([]);
  });

  it("pauses exactly the session it was given, not its neighbours", () => {
    addPause({ scope: "session", target: "s1", minutes: 60, cwd: work });
    expect(disableState({ cwd: work, sessionId: "s1" })).toMatchObject({ disabled: true, scope: "session", target: "s1" });
    expect(disableState({ cwd: work, sessionId: "s2" }).disabled).toBe(false);
    // the pause is keyed by session, so another run in the same directory stays protected
    expect(disableState({ cwd: work }).disabled).toBe(false);
  });

  it("pauses a directory and everything nested under it", () => {
    addPause({ scope: "path", target: work, minutes: 60 });
    expect(disableState({ cwd: work }).disabled).toBe(true);
    expect(disableState({ cwd: join(work, "packages", "api") }).disabled).toBe(true);
    expect(disableState({ cwd: tmpdir() }).disabled).toBe(false);
    // a sibling whose name merely starts with the same characters must NOT match
    expect(disableState({ cwd: `${work}-other` }).disabled).toBe(false);
  });

  // Regression: resolve() alone treats /var/x and /private/var/x (macOS) as two
  // different directories, so a pause recorded through one silently missed an
  // agent reporting the other.
  it("matches a directory reached through a SYMLINK", () => {
    const link = join(work, "link");
    const real = join(work, "real", "nested");
    mkdirSync(real, { recursive: true });
    symlinkSync(join(work, "real"), link);
    addPause({ scope: "path", target: join(work, "real"), minutes: 60 });
    expect(disableState({ cwd: link }).disabled).toBe(true);
    expect(disableState({ cwd: join(link, "nested") }).disabled).toBe(true);
    // and the reverse direction: paused through the link, matched on the real path
    clearPauses();
    addPause({ scope: "path", target: link, minutes: 60 });
    expect(disableState({ cwd: real }).disabled).toBe(true);
    // and re-enabling from the nested real path clears the pause set on the link
    expect(removePause("path", real)).toEqual([link]);
    expect(disableState({ cwd: real }).disabled).toBe(false);
  });

  // `enable` from a subdirectory must actually restore protection there; leaving
  // the parent pause in place would print "re-enabled" while staying off.
  it("removePause clears every ancestor pause covering the target", () => {
    const nested = join(work, "a", "b");
    mkdirSync(nested, { recursive: true });
    addPause({ scope: "path", target: work, minutes: 60 });
    addPause({ scope: "path", target: join(work, "a"), minutes: 60 });
    expect(removePause("path", nested).sort()).toEqual([work, join(work, "a")].sort());
    expect(disableState({ cwd: nested }).disabled).toBe(false);
  });

  it("expires on its own — an elapsed pause does not disable and is pruned", () => {
    writeFileSync(
      disabledPath(),
      JSON.stringify({
        version: 1,
        sessions: { s1: { until: new Date(Date.now() - 1000).toISOString() } },
        paths: { [work]: { until: new Date(Date.now() - 1000).toISOString() } },
      }),
    );
    expect(disableState({ cwd: work, sessionId: "s1" }).disabled).toBe(false);
    expect(activePauses()).toEqual([]);
  });

  it("honors --forever as an entry with no expiry", () => {
    expect(addPause({ scope: "path", target: work, minutes: null })).toBeNull();
    expect(disableState({ cwd: work })).toMatchObject({ disabled: true, scope: "path", until: undefined });
  });

  it("caps a pause at 24 h however many minutes are asked for", () => {
    const until = addPause({ scope: "session", target: "s1", minutes: 999_999 });
    expect(Date.parse(until!) - Date.now()).toBeLessThanOrEqual(1440 * 60_000 + 5_000);
  });

  it("removePause reports what it actually removed", () => {
    addPause({ scope: "session", target: "s1", minutes: 60 });
    expect(removePause("session", "s1")).toEqual(["s1"]);
    expect(removePause("session", "s1")).toEqual([]);
    expect(disableState({ sessionId: "s1" }).disabled).toBe(false);
  });

  it("clearPauses wipes every scope at once", () => {
    addPause({ scope: "session", target: "s1", minutes: 60 });
    addPause({ scope: "path", target: work, minutes: 60 });
    expect(clearPauses()).toBe(2);
    expect(activePauses()).toEqual([]);
  });

  // The store holds no secrets, but it decides whether the firewall runs — a
  // world-writable copy would be an off switch anyone on the box could flip.
  it("writes the store 0600 under a 0700 home", () => {
    addPause({ scope: "session", target: "s1", minutes: 60 });
    expect(statSync(disabledPath()).mode & 0o777).toBe(0o600);
    expect(statSync(home).mode & 0o777).toBe(0o700);
  });
});

describe("a corrupt or hostile store never disables the firewall", () => {
  it("ignores unparseable JSON", () => {
    writeFileSync(disabledPath(), "{ truncated");
    expect(disableState({ cwd: work, sessionId: "s1" }).disabled).toBe(false);
  });

  it("ignores an unknown schema version", () => {
    writeFileSync(disabledPath(), JSON.stringify({ version: 99, sessions: { s1: { until: null } } }));
    expect(disableState({ sessionId: "s1" }).disabled).toBe(false);
  });

  it("ignores entries whose expiry is not a date", () => {
    writeFileSync(disabledPath(), JSON.stringify({ version: 1, sessions: { s1: { until: "soon" } }, paths: {} }));
    expect(disableState({ sessionId: "s1" }).disabled).toBe(false);
  });

  it("ignores buckets of the wrong shape", () => {
    writeFileSync(disabledPath(), JSON.stringify({ version: 1, sessions: ["s1"], paths: null }));
    expect(disableState({ cwd: work, sessionId: "s1" }).disabled).toBe(false);
  });

  // The whole point of keeping the store under SECRETGATE_HOME: a repository you
  // clone must not be able to ship its own kill switch.
  it("ignores a project-local .secretgate.json claiming to be disabled", () => {
    writeFileSync(join(work, ".secretgate.json"), JSON.stringify({ enabled: false, disabled: true }));
    expect(disableState({ cwd: work }).disabled).toBe(false);
  });
});

describe("session-lifetime pause", () => {
  it("disables the run with no clock and reports the lifetime scope", () => {
    recordSession("s1", work);
    const until = addPause({ scope: "session", target: "s1", minutes: null, cwd: work, lifetime: true });
    expect(until).toBeNull();
    const st = disableState({ cwd: work, sessionId: "s1" });
    expect(st).toMatchObject({ disabled: true, scope: "session", target: "s1", lifetime: true });
    expect(st.until).toBeUndefined();
    // a new session (a new conversation) is protected without waiting on a timer
    expect(disableState({ cwd: work, sessionId: "s2" }).disabled).toBe(false);
  });

  it("carries no wall-clock expiry even when minutes are passed", () => {
    recordSession("s1", work);
    expect(addPause({ scope: "session", target: "s1", minutes: 60, cwd: work, lifetime: true })).toBeNull();
  });

  it("is garbage-collected once its session leaves the recent index (the run ended)", () => {
    recordSession("s1", work);
    addPause({ scope: "session", target: "s1", minutes: null, cwd: work, lifetime: true });
    expect(activePauses().some((p) => p.target === "s1")).toBe(true);
    // simulate the run ending: its id is no longer among the recent sessions
    writeFileSync(join(home, "sessions.json"), JSON.stringify({ version: 1, sessions: {} }));
    expect(activePauses().some((p) => p.target === "s1")).toBe(false);
    // and the next write compacts it out of the store for good
    addPause({ scope: "path", target: work, minutes: 60 });
    expect(JSON.parse(readFileSync(disabledPath(), "utf8")).sessions.s1).toBeUndefined();
  });

  it("keeps an explicit indefinite session pause even when the session is gone (back-compat)", () => {
    // lifetime NOT set: the old `--session <id> --forever` behaviour — held until
    // the user re-enables, never collected by the session index.
    addPause({ scope: "session", target: "ghost", minutes: null, cwd: work });
    writeFileSync(join(home, "sessions.json"), JSON.stringify({ version: 1, sessions: {} }));
    expect(activePauses().some((p) => p.target === "ghost")).toBe(true);
  });

  it("marks the lifetime scope in activePauses", () => {
    recordSession("s1", work);
    addPause({ scope: "session", target: "s1", minutes: null, cwd: work, lifetime: true });
    expect(activePauses().find((p) => p.target === "s1")?.lifetime).toBe(true);
  });

  it("never disables a fresh session because an uncollected orphan lingers", () => {
    // Even if an orphan is still on disk (no write has compacted it yet), the
    // hook matches only the CURRENT id, so a new run is safe.
    addPause({ scope: "session", target: "old-run", minutes: null, cwd: work, lifetime: true });
    expect(disableState({ cwd: work, sessionId: "brand-new" }).disabled).toBe(false);
  });
});

describe("session index", () => {
  it("maps a session to the directory it ran in, most recent first", () => {
    recordSession("s1", work);
    expect(sessionForCwd(work)).toBe("s1");
    recordSession("s2", work);
    expect(sessionForCwd(work)).toBe("s2");
    expect(sessionForCwd(tmpdir())).toBeUndefined();
  });

  it("resolves a session recorded in a parent directory", () => {
    const nested = join(work, "packages", "api");
    mkdirSync(nested, { recursive: true });
    recordSession("s1", work);
    expect(sessionForCwd(nested)).toBe("s1");
  });

  it("ignores incomplete input and survives a corrupt index", () => {
    recordSession(undefined, work);
    recordSession("s1", undefined);
    expect(sessionForCwd(work)).toBeUndefined();
    writeFileSync(join(home, "sessions.json"), "nope");
    expect(sessionForCwd(work)).toBeUndefined();
    expect(() => recordSession("s1", work)).not.toThrow();
    expect(sessionForCwd(work)).toBe("s1");
  });
});

describe("describeDisable", () => {
  it("names the scope, the target and the expiry", () => {
    expect(describeDisable({ disabled: false })).toBe("");
    expect(describeDisable({ disabled: true, scope: "env" })).toContain("SECRETGATE_DISABLE");
    expect(describeDisable({ disabled: true, scope: "session", target: "s1", until: "2030-01-01T00:00:00.000Z" })).toBe(
      "session s1 is paused until 2030-01-01T00:00:00.000Z",
    );
    expect(describeDisable({ disabled: true, scope: "path", target: "/proj" })).toBe("directory /proj is paused until re-enabled");
    expect(describeDisable({ disabled: true, scope: "session", target: "s1", lifetime: true })).toBe("session s1 is paused until the session ends");
  });
});
