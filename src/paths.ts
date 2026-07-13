import { pathMatchesGlob } from "./engine/allowlist.js";

// Files whose CONTENT is assumed sensitive: the firewall denies reading them
// outright (first line of defense — the secret never even enters a tool
// result). Users widen/narrow via `secretgate allow --path` and their agent's
// own permission config.
export const SENSITIVE_GLOBS = [
  "**/.env",
  "**/.env.*",
  "**/*.pem",
  "**/*.key",
  "**/id_rsa*",
  "**/id_ed25519*",
  "**/id_ecdsa*",
  "**/.aws/**",
  "**/.ssh/**",
  "**/.kube/config",
  "**/.npmrc",
  "**/.netrc",
  "**/.docker/config.json",
  "**/credentials.json",
];

// Template/sample files exist to be read — never sensitive.
export const EXEMPT_GLOBS = ["**/.env.example", "**/.env.sample", "**/.env.template", "**/.env.dist", "**/.env.defaults", "**/*.pub"];

// Globs above are rooted with `**/` so they match absolute and relative paths
// alike; `~` is expanded by the caller when needed.
export function sensitivePathMatch(path: string): string | undefined {
  const normalized = path.replaceAll("\\", "/");
  // case-insensitive: on macOS/Windows `.ENV` and `.env` are the SAME file, so
  // matching case-sensitively would let `Read(".ENV")` / `cat .ENV` slip past.
  if (EXEMPT_GLOBS.some((g) => pathMatchesGlob(normalized, g, true))) return undefined;
  return SENSITIVE_GLOBS.find((g) => pathMatchesGlob(normalized, g, true));
}

// Commands that print file contents to stdout — the ones that would leak a
// sensitive file INTO the model. A command that merely WRITES to a sensitive
// path (`echo x > .env`) does not leak and must not be denied (it's also the
// restore-on-write target). PostToolUse redaction is the backstop for anything
// this misses, so we can afford to be precise here.
const READ_COMMANDS = new Set([
  "cat",
  "head",
  "tail",
  "less",
  "more",
  "bat",
  "xxd",
  "od",
  "strings",
  "hexdump",
  "nl",
  "tac",
  "base64",
  "sed",
  "awk",
  "grep",
  "rg",
  "printf",
  "print",
]);

// Best-effort: only deny a Bash command when a recognized READ command
// references a sensitive path. Splits on shell separators so `foo && cat .env`
// is caught segment by segment. The agent's own permission rules and
// PostToolUse redaction are the stronger/backstop layers.
export function commandTouchesSensitivePath(command: string): string | undefined {
  for (const segment of command.split(/[;\n]|&&|\|\||\||&/)) {
    const tokens = segment.trim().split(/\s+/);
    if (tokens.length === 0) continue;
    const cmd = (tokens[0] ?? "").replace(/^.*\//, ""); // basename
    if (!READ_COMMANDS.has(cmd)) continue;
    for (const raw of tokens.slice(1)) {
      // stop at a write redirection target — that's not a read
      if (raw.startsWith(">")) break;
      const token = raw.replace(/^['"`]+|['"`]+$/g, "").replace(/^~\//, "/home/x/");
      if (token.length < 2 || token.startsWith("-")) continue;
      const hit = sensitivePathMatch(token);
      if (hit) return token;
    }
  }
  return undefined;
}
