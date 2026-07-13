#!/usr/bin/env node

// src/cli.ts
import { pathToFileURL } from "url";

// src/version.ts
var VERSION = "0.0.0";

// src/cli.ts
var USAGE = `secretgate ${VERSION} \u2014 local secrets firewall for coding agents

Usage: secretgate <command> [options]

Commands:
  install     Wire secretgate into an agent (--claude-code | --codex | --opencode | --all)
  uninstall   Remove exactly what install added
  status      Doctor: what is wired, versions, vault health, known limitations
  scan        Scan a file, directory or stdin (-) for secrets; exit 1 on findings
  pipe        Read stdin, write it back with secrets redacted to placeholders
  allow       Allowlist a value (hashed), a rule id (--rule) or a path glob (--path)
  vault       Manage the placeholder vault (list | clear) \u2014 never prints secrets
  hook        Internal: agent hook entrypoint (secretgate hook <agent> <event>)

Options:
  --version   Print the version
  --help      Print this help
`;
var commands = {};
async function run(argv, io) {
  const [first, ...rest] = argv;
  if (first === "--version" || first === "-v") {
    io.stdout(`${VERSION}
`);
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
    io.stderr(`Unknown command: ${first}

${USAGE}`);
    return 2;
  }
  return command(rest, io);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  run(process.argv.slice(2), {
    stdout: (s) => process.stdout.write(s),
    stderr: (s) => process.stderr.write(s)
  }).then((code) => {
    process.exitCode = code;
  });
}
export {
  run
};
