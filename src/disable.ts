import { randomBytes } from "node:crypto";
import { closeSync, mkdirSync, openSync, readFileSync, realpathSync, renameSync, writeSync } from "node:fs";
import { basename, dirname, join, resolve, sep } from "node:path";
import { defaultVaultHome } from "./vault/vault.js";

// The off switch. secretgate is a fail-closed firewall, so "off" is deliberately
// narrow and loud: every scope is time-bounded unless the user asks otherwise,
// the state lives ONLY under SECRETGATE_HOME (never inside a repository — a
// kill switch a cloned repo could ship would be a supply-chain hole), and the
// hooks announce the disabled state on every prompt.
//
// Three scopes, resolved in this order:
//   env     SECRETGATE_DISABLE=1 secretgate-aware-agent   — one process, no state
//   session `secretgate disable`            — one agent run, keyed by session id
//   path    `secretgate disable --project`  — one directory tree
//
// The session scope is time-bounded by default (a forgotten `disable` heals
// itself). `secretgate disable --session` makes it SESSION-LIFETIME instead: no
// clock, but collected the moment the run leaves the recent-session index, so a
// new session is protected with nothing to wait on and no stale state left.
//
// Placeholder RESTORE is never disabled by any of them: a disabled run must not
// leave dead SECRETGATE_ placeholders behind in files.

export type DisableScope = "env" | "session" | "path";

export interface DisableState {
  disabled: boolean;
  scope?: DisableScope;
  /** ISO expiry; absent when the scope has none (env, or an indefinite pause) */
  until?: string;
  /** session id or directory the match came from — for status and messages */
  target?: string;
  /** True when a session pause is bounded by the session's lifetime rather than a
   *  clock — it ends when the run ends, not at a timestamp. */
  lifetime?: boolean;
}

const NOT_DISABLED: DisableState = { disabled: false };

interface PauseEntry {
  /** ISO timestamp, or null for "until explicitly re-enabled" */
  until: string | null;
  cwd?: string;
  /** Session scope only: this pause lasts for the SESSION's lifetime. It carries
   *  no wall-clock expiry (`until` is null) and is garbage-collected the moment
   *  its session drops out of the recent-session index — i.e. the agent run
   *  ended — so a new session is protected again with no timer to wait on and no
   *  stale entry left behind. Absent on every other pause (back-compat). */
  lifetime?: true;
}

interface DisableFile {
  version: 1;
  sessions: Record<string, PauseEntry>;
  paths: Record<string, PauseEntry>;
}

interface SessionEntry {
  cwd: string;
  lastSeen: string;
  /** Monotonic write counter. Date.now() has millisecond resolution, so two
   *  sessions recorded in the same tick would tie and "most recent" would be a
   *  coin flip — and `disable` would pause the wrong run. */
  seq: number;
}

interface SessionFile {
  version: 1;
  sessions: Record<string, SessionEntry>;
}

// How many sessions the index remembers. Enough to cover every agent window a
// person realistically has open; the oldest are dropped beyond that.
const SESSION_INDEX_MAX = 20;

export const DEFAULT_DISABLE_MINUTES = 60;
export const MAX_DISABLE_MINUTES = 1440; // 24 h — beyond that, use --forever

function disablePath(): string {
  return join(defaultVaultHome(), "disabled.json");
}

function sessionIndexPath(): string {
  return join(defaultVaultHome(), "sessions.json");
}

// Same guarantee as the vault: final permissions from the very first byte
// (open(mode) then write, never write-then-chmod), renamed into place.
function writeFileAtomic(path: string, content: string, mode: number): void {
  mkdirSync(defaultVaultHome(), { recursive: true, mode: 0o700 });
  const tmp = `${path}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
  const fd = openSync(tmp, "w", mode);
  try {
    writeSync(fd, content);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, path);
}

function readJson<T>(path: string): T | undefined {
  try {
    return JSON.parse(readFileSync(path, "utf8")) as T;
  } catch {
    return undefined;
  }
}

function emptyDisableFile(): DisableFile {
  return { version: 1, sessions: {}, paths: {} };
}

// A missing OR corrupt store means "not disabled" — the fail-closed direction
// for this file: a firewall must never switch itself off because JSON got
// truncated.
function readDisableFile(): DisableFile {
  const parsed = readJson<DisableFile>(disablePath());
  if (parsed?.version !== 1) return emptyDisableFile();
  return {
    version: 1,
    sessions: isRecord(parsed.sessions) ? parsed.sessions : {},
    paths: isRecord(parsed.paths) ? parsed.paths : {},
  };
}

function isRecord(v: unknown): v is Record<string, PauseEntry> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function isLive(entry: PauseEntry | undefined, now: number): boolean {
  if (!entry) return false;
  if (entry.until === null) return true;
  const until = Date.parse(String(entry.until));
  return Number.isFinite(until) && until > now;
}

// Drop everything that has already expired, so the store stays a truthful
// picture of what is currently off (status reads it directly). Session-lifetime
// pauses have no clock to expire on, so they are collected the moment their
// session leaves the recent index — the "the agent run ended" signal. Only
// lifetime entries are collected this way: an explicit `--session <id> --forever`
// pause is kept until the user re-enables it, exactly as before.
//
// Called only from the write/status paths (addPause/removePause/activePauses),
// never from the hook's `disableState`, so reading the session index here costs
// nothing on the hot path — and `disableState` matches only the CURRENT session
// id, which a lifetime orphan (a DIFFERENT, ended session) can never equal, so a
// not-yet-collected orphan can never disable a live session.
function prune(file: DisableFile, now: number): DisableFile {
  const keepPaths = Object.fromEntries(Object.entries(file.paths).filter(([, e]) => isLive(e, now)));
  const live = liveSessionIds();
  const keepSessions = Object.fromEntries(Object.entries(file.sessions).filter(([id, e]) => isLive(e, now) && !(e.lifetime === true && !live.has(id))));
  return { version: 1, sessions: keepSessions, paths: keepPaths };
}

/** Session ids the index still remembers — the "these runs are still around"
 *  set that session-lifetime pauses are garbage-collected against. */
function liveSessionIds(): Set<string> {
  return new Set(Object.keys(readSessionIndex()));
}

export function envDisabled(): boolean {
  const raw = (process.env.SECRETGATE_DISABLE ?? "").trim().toLowerCase();
  return raw === "1" || raw === "true" || raw === "yes" || raw === "on";
}

// macOS symlinks /tmp and /var under /private, and homes are symlinked on plenty
// of setups, so resolve() alone makes ONE directory look like two: a pause
// recorded as /var/… would silently miss an agent reporting /private/var/…. The
// CLI already realpaths for this reason (isProcessEntrypoint,
// projectSettingsAliasesGlobal). Canonicalize the deepest ancestor that exists
// and re-append the rest, so a pause still covers directories created later.
function canonical(p: string): string {
  let head = resolve(p);
  const tail: string[] = [];
  for (;;) {
    try {
      return join(realpathSync(head), ...[...tail].reverse());
    } catch {
      const parent = dirname(head);
      if (parent === head) return resolve(p);
      tail.push(basename(head));
      head = parent;
    }
  }
}

// `dir` covers `cwd` when it IS cwd or an ancestor of it. The `sep` guard keeps
// a sibling like `/proj-old` from matching a pause on `/proj`.
function covers(dir: string, cwd: string): boolean {
  const a = canonical(dir);
  const b = canonical(cwd);
  return a === b || b.startsWith(a.endsWith(sep) ? a : a + sep);
}

/** The single question every hook asks: is secretgate off for this event? */
export function disableState(ctx: { cwd?: string; sessionId?: string } = {}): DisableState {
  if (envDisabled()) return { disabled: true, scope: "env" };
  const now = Date.now();
  const file = readDisableFile();

  if (ctx.sessionId) {
    const entry = file.sessions[ctx.sessionId];
    if (isLive(entry, now))
      return { disabled: true, scope: "session", until: entry?.until ?? undefined, target: ctx.sessionId, ...(entry?.lifetime ? { lifetime: true } : {}) };
  }
  if (ctx.cwd) {
    for (const [dir, entry] of Object.entries(file.paths)) {
      if (isLive(entry, now) && covers(dir, ctx.cwd)) return { disabled: true, scope: "path", until: entry.until ?? undefined, target: dir };
    }
  }
  return NOT_DISABLED;
}

/** Everything currently disabled, for `secretgate status`. */
export function activePauses(): Array<{ scope: "session" | "path"; target: string; until: string | null; lifetime?: boolean }> {
  const file = prune(readDisableFile(), Date.now());
  return [
    ...Object.entries(file.sessions).map(([target, e]) => ({ scope: "session" as const, target, until: e.until, lifetime: e.lifetime === true })),
    ...Object.entries(file.paths).map(([target, e]) => ({ scope: "path" as const, target, until: e.until })),
  ];
}

export interface PauseRequest {
  scope: "session" | "path";
  target: string;
  /** null => until explicitly re-enabled */
  minutes: number | null;
  cwd?: string;
  /** Session scope only: make this a session-lifetime pause (see
   *  `PauseEntry.lifetime`). Forces an indefinite `until` and lets the pause be
   *  collected once the session ends. Ignored for the path scope. */
  lifetime?: boolean;
}

/** Write a pause. Returns the ISO expiry, or null for an indefinite one. */
export function addPause(req: PauseRequest): string | null {
  const now = Date.now();
  const file = prune(readDisableFile(), now);
  const lifetime = req.scope === "session" && req.lifetime === true;
  // A lifetime pause is bounded by the session, not the clock, so it never carries
  // a wall-clock expiry regardless of what minutes were passed.
  const until = lifetime || req.minutes === null ? null : new Date(now + Math.min(req.minutes, MAX_DISABLE_MINUTES) * 60_000).toISOString();
  const entry: PauseEntry = req.scope === "session" && req.cwd ? { until, cwd: req.cwd } : { until };
  if (lifetime) entry.lifetime = true;
  file[req.scope === "session" ? "sessions" : "paths"][req.target] = entry;
  writeFileAtomic(disablePath(), JSON.stringify(file, null, 2), 0o600);
  return until;
}

/**
 * Remove the pauses that are keeping `target` disabled, and return them.
 *
 * For a directory that means every ANCESTOR pause covering it, not just an exact
 * match: `enable` run from a subdirectory of a paused tree must actually restore
 * protection there, and leaving a broader pause in place would report "re-enabled"
 * while the firewall stayed off.
 */
export function removePause(scope: "session" | "path", target: string): string[] {
  const file = prune(readDisableFile(), Date.now());
  const bucket = file[scope === "session" ? "sessions" : "paths"];
  const keys = scope === "path" ? Object.keys(bucket).filter((d) => covers(d, target)) : target in bucket ? [target] : [];
  for (const key of keys) delete bucket[key];
  writeFileAtomic(disablePath(), JSON.stringify(file, null, 2), 0o600);
  return keys;
}

/** Wipe every pause — the "whatever is off, turn it back on" escape hatch. */
export function clearPauses(): number {
  const before = activePauses().length;
  writeFileAtomic(disablePath(), JSON.stringify(emptyDisableFile(), null, 2), 0o600);
  return before;
}

// The session index exists so `secretgate disable`, run from inside an agent
// session, can pause THAT run rather than the whole directory. Hooks call this
// only on prompt submit, and it writes only when the id is new or its cwd moved
// — one write per session in practice.
function readSessionIndex(): Record<string, SessionEntry> {
  const parsed = readJson<SessionFile>(sessionIndexPath());
  if (parsed?.version !== 1 || !isRecord(parsed.sessions)) return {};
  return parsed.sessions as unknown as Record<string, SessionEntry>;
}

const bySeqDesc = (a: [string, SessionEntry], b: [string, SessionEntry]): number => (b[1]?.seq ?? 0) - (a[1]?.seq ?? 0);

export function recordSession(sessionId: string | undefined, cwd: string | undefined): void {
  if (!sessionId || !cwd) return;
  try {
    const sessions = readSessionIndex();
    if (sessions[sessionId]?.cwd === cwd) return;
    const nextSeq = Math.max(0, ...Object.values(sessions).map((e) => e?.seq ?? 0)) + 1;
    sessions[sessionId] = { cwd, lastSeen: new Date().toISOString(), seq: nextSeq };
    const trimmed = Object.entries(sessions).sort(bySeqDesc).slice(0, SESSION_INDEX_MAX);
    writeFileAtomic(sessionIndexPath(), JSON.stringify({ version: 1, sessions: Object.fromEntries(trimmed) } satisfies SessionFile, null, 2), 0o600);
  } catch {
    // The index is a convenience for the CLI. Never let it break a hook.
  }
}

/** Most recently active session started in (or under) `cwd`, if any. */
export function sessionForCwd(cwd: string): string | undefined {
  return Object.entries(readSessionIndex())
    .filter(([, e]) => typeof e?.cwd === "string" && covers(e.cwd, cwd))
    .sort(bySeqDesc)[0]?.[0];
}

/** One-line summary used by hook system messages and by `status`. */
export function describeDisable(state: DisableState): string {
  if (!state.disabled) return "";
  const where =
    state.scope === "env"
      ? "SECRETGATE_DISABLE is set for this process"
      : state.scope === "session"
        ? `session ${state.target} is paused`
        : `directory ${state.target} is paused`;
  const when = state.until ? ` until ${state.until}` : state.lifetime ? " until the session ends" : state.scope === "env" ? "" : " until re-enabled";
  return `${where}${when}`;
}
