import { execFileSync } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, statSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { loadConfig } from "./config.js";
import { pathMatchesGlob, sha256 } from "./engine/allowlist.js";
import type { Finding } from "./engine/scanner.js";
import { scan, sensitiveFileNameRule } from "./engine/scanner.js";
import { handleClaudeCode } from "./hooks/claude-code.js";
import { handleCodex } from "./hooks/codex.js";
import { writeAllow } from "./install/allow-store.js";
import { installClaudeCode, uninstallClaudeCode } from "./install/claude-code.js";
import { codexHome, installCodex, uninstallCodex } from "./install/codex.js";
import { SettingsParseError } from "./install/json-merge.js";
import { installOpencode, opencodeConfigDir, uninstallOpencode } from "./install/opencode.js";
import { redactText } from "./redact.js";
import { Vault, defaultVaultHome } from "./vault/vault.js";
import { VERSION } from "./version.js";

export interface Io {
  stdout: (s: string) => void;
  stderr: (s: string) => void;
  stdin?: () => Promise<string>;
}

const USAGE = `secretgate ${VERSION} — local secrets firewall for coding agents

Usage: secretgate <command> [options]

Commands:
  init        One-shot: install for the agents on this machine and verify the firewall fires
  install     Wire secretgate into an agent (--claude-code | --codex | --opencode | --all)
  uninstall   Remove exactly what install added
  status      Doctor: what is wired, versions, vault health, known limitations
  scan        Scan a file, directory or stdin (-) for secrets; exit 1 on findings
  pipe        Read stdin, write it back with secrets redacted to placeholders
  allow       Allowlist a value (hashed), a rule id (--rule) or a path glob (--path)
  vault       Manage the placeholder vault (list | clear) — never prints secrets
  hook        Internal: agent hook entrypoint (secretgate hook <agent> <event>)

Options:
  --version   Print the version
  --help      Print this help
`;

// Read stdin, but STOP once we exceed `cap` bytes — an unbounded read would OOM
// (and crash) the hook on a huge tool output, which the agent treats as
// fail-open. Returns whether the stream was truncated so the caller can
// fail CLOSED instead of scanning a partial payload.
async function readIoStdinCapped(io: Io, cap: number): Promise<{ text: string; truncated: boolean }> {
  if (io.stdin) {
    const text = await io.stdin();
    return { text, truncated: text.length > cap };
  }
  let data = "";
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) {
    data += chunk;
    if (data.length > cap) return { text: data.slice(0, cap), truncated: true };
  }
  return { text: data, truncated: false };
}

async function readIoStdin(io: Io): Promise<string> {
  if (io.stdin) return io.stdin();
  let data = "";
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) data += chunk;
  return data;
}

const SKIP_DIRS = new Set([".git", "node_modules", ".pnpm", "dist", "coverage", ".venv", "__pycache__"]);
const MAX_FILE_BYTES = 2 * 1024 * 1024;

function* walkFiles(root: string): Generator<string> {
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    if (entry.isSymbolicLink()) continue;
    const full = join(root, entry.name);
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) yield* walkFiles(full);
    } else if (entry.isFile()) {
      yield full;
    }
  }
}

function readTextFile(path: string): string | undefined {
  const stats = statSync(path);
  if (stats.size === 0 || stats.size > MAX_FILE_BYTES) return undefined;
  const buf = readFileSync(path);
  const probe = buf.subarray(0, 8192);
  if (probe.includes(0)) return undefined; // binary
  return buf.toString("utf8");
}

function hashPrefix(secret: string): string {
  return sha256(secret).slice(0, 12);
}

interface ScanHit {
  finding: Finding;
  path: string;
}

async function cmdScan(args: string[], io: Io): Promise<number> {
  let json = false;
  const excludes: string[] = [];
  let target: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === "--json") json = true;
    else if (a === "--exclude") {
      const g = args[++i];
      if (!g) {
        io.stderr("scan: --exclude requires a glob\n");
        return 2;
      }
      excludes.push(g);
    } else if (!target) target = a;
    else {
      io.stderr(`scan: unexpected argument ${a}\n`);
      return 2;
    }
  }
  if (!target) {
    io.stderr("scan: expected a file, a directory or '-' for stdin\n");
    return 2;
  }

  const cfg = loadConfig(process.cwd());
  const hits: ScanHit[] = [];

  if (target === "-") {
    const text = await readIoStdin(io);
    for (const finding of scan(text, { allowlist: cfg.allowlist })) hits.push({ finding, path: "stdin" });
  } else {
    const root = resolve(target);
    const stats = statSync(root, { throwIfNoEntry: false });
    if (!stats) {
      io.stderr(`scan: no such file or directory: ${target}\n`);
      return 2;
    }
    const files = stats.isDirectory() ? [...walkFiles(root)] : [root];
    for (const file of files) {
      const rel = stats.isDirectory() ? relative(root, file) : file;
      if (excludes.some((g) => pathMatchesGlob(rel, g))) continue;
      if (cfg.allowlist.paths?.some((g) => pathMatchesGlob(rel, g))) continue;
      const nameRule = sensitiveFileNameRule(rel);
      if (nameRule) {
        hits.push({ finding: { ruleId: nameRule, match: rel, secret: "", start: 0, end: 0, entropy: 0, line: 0 }, path: rel });
        continue;
      }
      const text = readTextFile(file);
      if (text === undefined) continue;
      for (const finding of scan(text, { sourcePath: rel, allowlist: cfg.allowlist })) hits.push({ finding, path: rel });
    }
  }

  if (json) {
    io.stdout(
      `${JSON.stringify(
        {
          version: VERSION,
          findings: hits.map(({ finding, path }) => ({
            ruleId: finding.ruleId,
            path,
            line: finding.line + 1,
            entropy: Number(finding.entropy.toFixed(3)),
            length: finding.secret.length,
            sha256: hashPrefix(finding.secret),
          })),
        },
        null,
        2,
      )}\n`,
    );
  } else if (hits.length === 0) {
    io.stdout("secretgate: no secrets found\n");
  } else {
    for (const { finding, path } of hits) {
      const detail =
        finding.secret === ""
          ? "[sensitive file name]"
          : `[len ${finding.secret.length}, entropy ${finding.entropy.toFixed(2)}, sha256 ${hashPrefix(finding.secret)}]`;
      io.stdout(`${path}:${finding.line + 1}  ${finding.ruleId}  ${detail}\n`);
    }
    io.stdout(`secretgate: ${hits.length} finding(s). Allow a value with \`secretgate allow <value>\`.\n`);
  }
  return hits.length > 0 ? 1 : 0;
}

async function cmdPipe(_args: string[], io: Io): Promise<number> {
  const text = await readIoStdin(io);
  const cfg = loadConfig(process.cwd());
  const vault = new Vault();
  const r = redactText(text, vault, "pipe", { allowlist: cfg.allowlist });
  io.stdout(r.text);
  return 0;
}

async function cmdAllow(args: string[], io: Io): Promise<number> {
  if (args[0] === "--rule" && args[1]) {
    writeAllow({ rules: [args[1]] });
    io.stdout(`secretgate: rule '${args[1]}' allowlisted\n`);
    return 0;
  }
  if (args[0] === "--path" && args[1]) {
    writeAllow({ paths: [args[1]] });
    io.stdout(`secretgate: path glob '${args[1]}' allowlisted\n`);
    return 0;
  }
  const value = args[0];
  if (!value || value.startsWith("--")) {
    io.stderr("allow: expected <value>, --rule <id> or --path <glob>\n");
    return 2;
  }
  writeAllow({ sha256: [sha256(value)] });
  io.stdout(`secretgate: value allowlisted (stored as sha256 ${sha256(value).slice(0, 12)}…, never in clear)\n`);
  return 0;
}

async function cmdVault(args: string[], io: Io): Promise<number> {
  const vault = new Vault();
  if (args[0] === "list") {
    const entries = vault.list();
    if (entries.length === 0) {
      io.stdout("secretgate: vault is empty\n");
      return 0;
    }
    for (const e of entries) {
      io.stdout(`${e.placeholder}  ${e.ruleId}  first seen ${e.firstSeen}  sources: ${e.sources.join(", ")}\n`);
    }
    return 0;
  }
  if (args[0] === "clear") {
    vault.clear();
    io.stdout("secretgate: vault cleared\n");
    return 0;
  }
  io.stderr("vault: expected 'list' or 'clear'\n");
  return 2;
}

// Hooks fire on every prompt/tool call. HARD_READ_CAP is the OOM guard (stop
// reading past it); SCAN_CAP is the largest payload we will scan — beyond it we
// fail CLOSED (block / deny / withhold). SCAN_CAP is deliberately small so that
// even the slowest single rule over it stays well under the in-scan wall-clock
// deadline (a rule's regex is atomic — the deadline is only checked between
// rules). The deadline bounds the aggregate; the cap bounds any one rule. A
// larger prompt/output is withheld, never leaked. Real tool outputs are far
// under 2 MB.
const HARD_READ_CAP = 64 * 1024 * 1024;
const SCAN_CAP = 2 * 1024 * 1024;

async function cmdHook(args: string[], io: Io): Promise<number> {
  const [agent, event] = args;
  if (!agent || !event) {
    io.stderr("hook: usage: secretgate hook <agent> <event>\n");
    return 2;
  }
  let raw: string;
  try {
    const read = await readIoStdinCapped(io, HARD_READ_CAP);
    // Truncated or over the scan cap -> non-JSON sentinel -> handler fails CLOSED.
    raw = read.truncated || read.text.length > SCAN_CAP ? "__SECRETGATE_OVERSIZED__" : read.text;
  } catch {
    raw = "__SECRETGATE_STDIN_ERROR__";
  }
  if (agent === "claude-code" || agent === "codex") {
    const r = agent === "codex" ? await handleCodex(event, raw) : await handleClaudeCode(event, raw);
    if (r.stdout) io.stdout(r.stdout);
    return r.exit;
  }
  io.stderr(`hook: unknown agent '${agent}'\n`);
  return 2;
}

// The settings entry must keep working after npx caches are evicted and
// across package updates, so install pins a copy of the running bundle under
// the secretgate home and references that absolute path.
function installedCliCommand(): string {
  const self = fileURLToPath(import.meta.url);
  if (!self.endsWith(".mjs")) return `node "${self}"`; // dev checkout
  const target = join(defaultVaultHome(), "bin", "secretgate.mjs");
  mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
  copyFileSync(self, target);
  chmodSync(target, 0o755);
  return `node "${target}"`;
}

interface AgentFlags {
  claudeCode: boolean;
  codex: boolean;
  opencode: boolean;
  project: boolean;
}

function parseAgentFlags(args: string[], io: Io): AgentFlags | undefined {
  const flags: AgentFlags = { claudeCode: false, codex: false, opencode: false, project: false };
  for (const a of args) {
    if (a === "--claude-code") flags.claudeCode = true;
    else if (a === "--codex") flags.codex = true;
    else if (a === "--opencode") flags.opencode = true;
    else if (a === "--all") flags.claudeCode = flags.codex = flags.opencode = true;
    else if (a === "--project") flags.project = true;
    else {
      io.stderr(`unknown option: ${a}\n`);
      return undefined;
    }
  }
  if (!flags.claudeCode && !flags.codex && !flags.opencode) {
    io.stderr("expected at least one agent: --claude-code | --codex | --opencode | --all\n");
    return undefined;
  }
  return flags;
}

function opencodePluginSource(): string {
  const selfDir = dirname(fileURLToPath(import.meta.url));
  const candidates = [join(selfDir, "secretgate-opencode.mjs"), join(selfDir, "..", "scripts", "secretgate-opencode.mjs")];
  const found = candidates.find((c) => existsSync(c));
  if (!found) throw new Error("cannot locate secretgate-opencode.mjs next to the CLI bundle — reinstall the package");
  return found;
}

function claudeSettingsPath(project: boolean): string {
  return project ? join(process.cwd(), ".claude", "settings.json") : join(homedir(), ".claude", "settings.json");
}

function installForAgents(flags: AgentFlags, io: Io): void {
  if (flags.claudeCode) {
    const settingsPath = claudeSettingsPath(flags.project);
    mkdirSync(dirname(settingsPath), { recursive: true });
    const r = installClaudeCode({ settingsPath, command: installedCliCommand() });
    io.stdout(`claude-code: ${r.changed ? "wired" : "already up to date"} (${r.path})\n`);
    if (r.backupPath) io.stdout(`claude-code: previous settings backed up to ${r.backupPath}\n`);
    io.stdout("claude-code: restart your Claude Code session so the hooks load.\n");
    io.stdout("claude-code: note — @file mentions bypass tool hooks; permissions.deny rules cover the common sensitive files.\n");
  }
  if (flags.opencode) {
    const r = installOpencode({ configDir: opencodeConfigDir(), pluginSource: opencodePluginSource() });
    io.stdout(`opencode: ${r.changed ? "wired" : "already up to date"} (${r.path})\n`);
    io.stdout("opencode: restart OpenCode so the plugin loads.\n");
  }
  if (flags.codex) {
    const dir = codexHome();
    mkdirSync(dir, { recursive: true });
    const r = installCodex({ codexDir: dir, command: installedCliCommand() });
    io.stdout(`codex: ${r.hooks.changed || r.configChanged ? "wired" : "already up to date"} (${dir})\n`);
    for (const g of r.guidance) io.stdout(`${g}\n`);
    io.stdout("codex: restart your Codex session so the hooks load (review them with /hooks).\n");
  }
}

function handleInstallError(err: unknown, io: Io): number | undefined {
  if (err instanceof SettingsParseError) {
    io.stderr(`${err.message}\n`);
    return 2;
  }
  if (err instanceof Error && /hooks = false|refusing/.test(err.message)) {
    io.stderr(`${err.message}\n`);
    return 2;
  }
  return undefined;
}

async function cmdInstall(args: string[], io: Io): Promise<number> {
  const flags = parseAgentFlags(args, io);
  if (!flags) return 2;
  try {
    installForAgents(flags, io);
  } catch (err) {
    const code = handleInstallError(err, io);
    if (code !== undefined) return code;
    throw err;
  }
  return 0;
}

// Which agents are present on this machine (config dir / home exists).
function detectAgents(): AgentFlags {
  return {
    claudeCode: existsSync(join(homedir(), ".claude")),
    codex: existsSync(codexHome()),
    opencode: existsSync(opencodeConfigDir()),
    project: false,
  };
}

// End-to-end self-test: spawn the EXACT wired bundle with a synthetic event and
// confirm it (1) blocks a secret-bearing prompt and (2) redacts a secret in
// tool output. Runs against a throwaway vault so the real one stays clean.
function verifyClaudeCodeWiring(io: Io): boolean {
  const pinned = join(defaultVaultHome(), "bin", "secretgate.mjs");
  const self = fileURLToPath(import.meta.url);
  const bundle = existsSync(pinned) ? pinned : self;
  // high-entropy fake token, built by concatenation (never a literal in-repo)
  const fake = "ghp_" + ["aB3dE6", "gH9jK2", "mN5pQ8", "sT1vW4", "yZ7bC0", "dF6hJ9"].join("");
  const tmpHome = mkdtempSync(join(tmpdir(), "secretgate-verify-"));
  const env = { ...process.env, SECRETGATE_HOME: tmpHome };
  const runHook = (event: string, payload: unknown): any => {
    const out = execFileSync("node", [bundle, "hook", "claude-code", event], { input: JSON.stringify(payload), env, encoding: "utf8" });
    return out.trim() ? JSON.parse(out) : {};
  };
  let ok = true;
  try {
    const block = runHook("user-prompt-submit", { hook_event_name: "UserPromptSubmit", cwd: tmpHome, prompt: `deploy with ${fake}` });
    if (block.decision === "block" && !JSON.stringify(block).includes(fake)) {
      io.stdout("  ✓ a secret pasted in a prompt is blocked (and the raw value is not echoed)\n");
    } else {
      io.stdout("  ✗ prompt block FAILED — a pasted secret would reach the model\n");
      ok = false;
    }
    const post = runHook("post-tool-use", {
      hook_event_name: "PostToolUse",
      cwd: tmpHome,
      tool_name: "Bash",
      tool_input: { command: "env" },
      tool_response: `PATH=/bin\nTOKEN=${fake}\n`,
    });
    const redacted = post?.hookSpecificOutput?.updatedToolOutput ?? "";
    if (typeof redacted === "string" && redacted.includes("SECRETGATE_") && !redacted.includes(fake)) {
      io.stdout("  ✓ a secret in tool output is redacted before the model sees it\n");
    } else {
      io.stdout("  ✗ tool-output redaction FAILED — a secret would reach the model\n");
      ok = false;
    }
  } catch (err) {
    io.stdout(`  ✗ could not run the wired hook: ${err instanceof Error ? err.message.split("\n")[0] : "unknown"}\n`);
    ok = false;
  } finally {
    rmSync(tmpHome, { recursive: true, force: true });
  }
  return ok;
}

// `init` — the one-shot: install for the agents on this machine (or the ones
// named), then PROVE the protection actually fires end-to-end.
async function cmdInit(args: string[], io: Io): Promise<number> {
  let flags: AgentFlags;
  const explicit = args.some((a) => a.startsWith("--") && a !== "--project");
  if (explicit) {
    const parsed = parseAgentFlags(args, io);
    if (!parsed) return 2;
    flags = parsed;
  } else {
    flags = detectAgents();
    flags.project = args.includes("--project");
    if (!flags.claudeCode && !flags.codex && !flags.opencode) {
      io.stdout("secretgate: no agent config found — defaulting to Claude Code.\n");
      flags.claudeCode = true;
    } else {
      const found = [flags.claudeCode && "Claude Code", flags.codex && "Codex", flags.opencode && "OpenCode"].filter(Boolean).join(", ");
      io.stdout(`secretgate: detected ${found} — wiring ${found === "Claude Code" ? "it" : "them"}.\n`);
    }
  }

  io.stdout("\n== install ==\n");
  try {
    installForAgents(flags, io);
  } catch (err) {
    const code = handleInstallError(err, io);
    if (code !== undefined) return code;
    throw err;
  }

  io.stdout("\n== verify the firewall actually fires ==\n");
  let ok = true;
  if (flags.claudeCode) ok = verifyClaudeCodeWiring(io) && ok;
  if (flags.codex) io.stdout("  · codex: prompt/tool-input protection installed (tool-output redaction is not possible on Codex yet).\n");
  if (flags.opencode) io.stdout("  · opencode: plugin installed; restart OpenCode to load it.\n");

  io.stdout("\n");
  if (ok) {
    io.stdout("secretgate is active. Restart your agent session so the hooks load, then you're protected.\n");
    return 0;
  }
  io.stderr("secretgate: verification FAILED — protection may not be active. Run `secretgate status` and re-run `secretgate init`.\n");
  return 1;
}

async function cmdUninstall(args: string[], io: Io): Promise<number> {
  const flags = parseAgentFlags(args, io);
  if (!flags) return 2;
  try {
    if (flags.claudeCode) {
      const r = uninstallClaudeCode({ settingsPath: claudeSettingsPath(flags.project) });
      io.stdout(`claude-code: ${r.changed ? "unwired" : "nothing to remove"} (${r.path})\n`);
    }
    if (flags.opencode) {
      const r = uninstallOpencode({ configDir: opencodeConfigDir() });
      io.stdout(`opencode: ${r.changed ? "unwired" : "nothing to remove"} (${r.path})\n`);
    }
    if (flags.codex) {
      const r = uninstallCodex({ codexDir: codexHome() });
      io.stdout(`codex: ${r.hooks.changed || r.configChanged ? "unwired" : "nothing to remove"} (${codexHome()})\n`);
    }
  } catch (err) {
    if (err instanceof SettingsParseError) {
      io.stderr(`${err.message}\n`);
      return 2;
    }
    throw err;
  }
  io.stdout("secretgate: the vault (~/.secretgate) is kept — remove it manually if you want the mappings gone.\n");
  return 0;
}

function readJsonSafe(path: string): Record<string, any> | undefined {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return undefined;
  }
}

function hookWireCount(settings: Record<string, any> | undefined, marker: string): number {
  if (!settings?.hooks) return 0;
  let count = 0;
  for (const groups of Object.values(settings.hooks as Record<string, Array<{ hooks?: Array<{ command?: string }> }>>)) {
    if (!Array.isArray(groups)) continue;
    for (const g of groups) for (const h of g.hooks ?? []) if (String(h.command ?? "").includes(marker)) count++;
  }
  return count;
}

async function cmdStatus(_args: string[], io: Io): Promise<number> {
  io.stdout(`secretgate ${VERSION}\n\n`);

  // pinned bundle
  const pinned = join(defaultVaultHome(), "bin", "secretgate.mjs");
  if (existsSync(pinned)) {
    const pinnedVersion = /VERSION = "([^"]+)"/.exec(readFileSync(pinned, "utf8"))?.[1] ?? "unknown";
    io.stdout(`bundle    pinned at ${pinned} (v${pinnedVersion}${pinnedVersion !== VERSION ? ` — CLI is v${VERSION}, re-run install to refresh` : ""})\n`);
  } else {
    io.stdout("bundle    not pinned yet (run `secretgate install …`)\n");
  }

  // claude code
  for (const [label, path] of [
    ["global ", claudeSettingsPath(false)],
    ["project", claudeSettingsPath(true)],
  ] as const) {
    const settings = readJsonSafe(path);
    const wired = hookWireCount(settings, "hook claude-code");
    const denies = Array.isArray(settings?.permissions?.deny) ? settings.permissions.deny.filter((d: string) => d.startsWith("Read(")).length : 0;
    io.stdout(`claude-code ${label}  ${wired > 0 ? `wired (${wired} hooks, ${denies} Read deny rules)` : "not wired"}  ${path}\n`);
  }
  io.stdout("claude-code limitation: @file mentions bypass tool hooks (deny rules are the only cover there).\n");

  // codex
  const codexHooks = readJsonSafe(join(codexHome(), "hooks.json"));
  const codexWired = hookWireCount(codexHooks, "hook codex");
  let codexFeature = false;
  try {
    codexFeature = /^\s*hooks\s*=\s*true\b/m.test(readFileSync(join(codexHome(), "config.toml"), "utf8"));
  } catch {}
  io.stdout(
    `codex     ${codexWired > 0 && codexFeature ? `wired (${codexWired} hooks, feature gate on)` : codexWired > 0 ? "hooks present but [features] hooks = true is MISSING" : "not wired"}  ${codexHome()}\n`,
  );
  if (codexWired > 0) io.stdout("codex     limitations: interactive sessions only (`codex exec` bug); no tool-output redaction upstream yet.\n");

  // opencode
  const ocPlugin = join(opencodeConfigDir(), "plugin", "secretgate.js");
  const ocConfig = readJsonSafe(join(opencodeConfigDir(), "opencode.json"));
  const ocPinned = Array.isArray(ocConfig?.plugin) && ocConfig.plugin.some((p: string) => /^secretgate@/.test(p));
  io.stdout(`opencode  ${existsSync(ocPlugin) ? `wired (plugin file)` : ocPinned ? "wired (opencode.json npm pin)" : "not wired"}  ${opencodeConfigDir()}\n`);

  // engines
  const { gitleaksPath } = await import("./engine/gitleaks-bin.js");
  const gl = gitleaksPath();
  io.stdout(`engines   built-in JS rules${gl ? ` + gitleaks binary (${gl})` : " (gitleaks binary not found — `scan` runs JS engine only)"}\n`);

  // vault
  const vault = new Vault();
  const entries = vault.list();
  io.stdout(`vault     ${defaultVaultHome()} — ${entries.length} placeholder(s)`);
  try {
    const mode = statSync(join(defaultVaultHome(), "vault.json")).mode & 0o777;
    io.stdout(mode === 0o600 ? "\n" : ` — WARNING: vault.json is ${mode.toString(8)}, expected 600\n`);
  } catch {
    io.stdout(" (no vault file yet)\n");
  }
  return 0;
}

type Command = (args: string[], io: Io) => Promise<number> | number;

const commands: Record<string, Command> = {
  init: cmdInit,
  scan: cmdScan,
  pipe: cmdPipe,
  allow: cmdAllow,
  vault: cmdVault,
  install: cmdInstall,
  uninstall: cmdUninstall,
  status: cmdStatus,
  hook: cmdHook,
};

export async function run(argv: string[], io: Io): Promise<number> {
  const [first, ...rest] = argv;
  if (first === "--version" || first === "-v") {
    io.stdout(`${VERSION}\n`);
    return 0;
  }
  if (first === "--help" || first === "-h") {
    io.stdout(USAGE);
    return 0;
  }
  if (!first) {
    io.stderr(USAGE);
    return 2;
  }
  const command = commands[first];
  if (!command) {
    io.stderr(`Unknown command: ${first}\n\n${USAGE}`);
    return 2;
  }
  return command(rest, io);
}

// Are we the process entrypoint? Compare REAL paths: the installed hook
// invokes the pinned bundle under ~/.secretgate, and on macOS common homes
// (/tmp, /var, and some corporate setups) resolve through symlinks — so
// `import.meta.url` (real) and `process.argv[1]` (as-typed) diverge. Without
// realpath the guard would silently fail and the hook would emit nothing
// (fail-open). Resolve both sides before comparing.
function isProcessEntrypoint(): boolean {
  const argv1 = process.argv[1];
  if (!argv1) return false;
  const selfPath = fileURLToPath(import.meta.url);
  try {
    return realpathSync(selfPath) === realpathSync(argv1);
  } catch {
    return import.meta.url === pathToFileURL(argv1).href;
  }
}

/* node:coverage ignore next -- process entrypoint, exercised via the bundle smoke */
if (isProcessEntrypoint()) {
  run(process.argv.slice(2), {
    stdout: (s) => process.stdout.write(s),
    stderr: (s) => process.stderr.write(s),
  }).then((code) => {
    process.exitCode = code;
  });
}
