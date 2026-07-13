import { pathToFileURL } from "node:url";
import { VERSION } from "./version.js";

export interface Io {
  stdout: (s: string) => void;
  stderr: (s: string) => void;
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

type Command = (args: string[], io: Io) => Promise<number> | number;

const commands: Record<string, Command> = {};

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
