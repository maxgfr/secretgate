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
  if (EXEMPT_GLOBS.some((g) => pathMatchesGlob(normalized, g))) return undefined;
  return SENSITIVE_GLOBS.find((g) => pathMatchesGlob(normalized, g));
}

// Best-effort scan of a shell command for sensitive path mentions: split into
// tokens, strip quotes/common decorations, match each. Catches `cat .env`,
// `head ~/.aws/credentials`… (the agent's own permission rules are the
// stronger layer for shell reads; this is belt-and-braces).
export function commandTouchesSensitivePath(command: string): string | undefined {
  for (const raw of command.split(/[\s;|&()<>]+/)) {
    const token = raw.replace(/^['"`]+|['"`]+$/g, "").replace(/^~\//, "/home/x/");
    if (token.length < 2 || token.startsWith("-")) continue;
    const hit = sensitivePathMatch(token);
    if (hit) return token;
  }
  return undefined;
}
