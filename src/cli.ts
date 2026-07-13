import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { loadConfig } from "./config.js";
import { pathMatchesGlob, sha256 } from "./engine/allowlist.js";
import type { Finding } from "./engine/scanner.js";
import { scan } from "./engine/scanner.js";
import { redactText } from "./redact.js";
import { writeAllow } from "./install/allow-store.js";
import { Vault } from "./vault/vault.js";
import { VERSION } from "./version.js";

export interface Io {
  stdout: (s: string) => void;
  stderr: (s: string) => void;
  stdin?: () => Promise<string>;
}

const USAGE = `secretgate ${VERSION} — local secrets firewall for coding agents

Usage: secretgate <command> [options]

Commands:
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
      io.stdout(
        `${path}:${finding.line + 1}  ${finding.ruleId}  [len ${finding.secret.length}, entropy ${finding.entropy.toFixed(2)}, sha256 ${hashPrefix(finding.secret)}]\n`,
      );
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

function notImplemented(name: string) {
  return (_args: string[], io: Io): number => {
    io.stderr(`secretgate ${name}: not implemented yet\n`);
    return 2;
  };
}

type Command = (args: string[], io: Io) => Promise<number> | number;

const commands: Record<string, Command> = {
  scan: cmdScan,
  pipe: cmdPipe,
  allow: cmdAllow,
  vault: cmdVault,
  install: notImplemented("install"),
  uninstall: notImplemented("uninstall"),
  status: notImplemented("status"),
  hook: notImplemented("hook"),
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

/* node:coverage ignore next -- process entrypoint, exercised via the bundle smoke */
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  run(process.argv.slice(2), {
    stdout: (s) => process.stdout.write(s),
    stderr: (s) => process.stderr.write(s),
  }).then((code) => {
    process.exitCode = code;
  });
}
