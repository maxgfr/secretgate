// Fake tokens for tests, ALWAYS built by concatenation so this repo never
// contains a token-shaped literal (keeps our own self-scan CI job and GitHub
// push protection quiet). None of these are real credentials.
export const FAKE = {
  // aws-access-token: \b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b, entropy > 3.
  // Must NOT end in EXAMPLE — upstream allowlists `.+EXAMPLE$` (AWS docs keys).
  awsKeyId: "AKIA" + "Q7R2M3XBL4WPZ6TK",
  // github-pat: ghp_[0-9a-zA-Z]{36}
  githubPat: "ghp_" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0dF6hJ9",
  // anthropic-api-key: \b(sk-ant-api03-[a-zA-Z0-9_\-]{93}AA)
  anthropicKey: "sk-ant-" + "api03-" + "kQ9zX2mP7vB4wL8nR3tY6hG5jD1fC0aS_eU-iO".repeat(2) + "kQ9zX2mP7vB4wL8nR" + "AA",
  // slack-bot-token: xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*, entropy > 3
  slackBotToken: "xoxb-" + "1046385290713" + "-" + "9182736450192" + "-aBcDeFgHiJkLmNoPqRsT",
  // generic-api-key secret group: [\w.=-]{10,150}, entropy > 3.5
  genericSecret: "kQ9zX2mP7v" + "B4wL8nR3tY" + "6hG5jD1fC0",
  // private-key: -----BEGIN ... PRIVATE KEY----- ... KEY-----
  // biome-ignore format: keep the pragma on the secret-bearing line
  privateKey: ["-----BEGIN RSA PRIVATE KEY-----", ("MIIEkQ9zX2mP7vB4wL8nR3tY6hG5jD1fC0aSeUiO".repeat(2) + "=="), "-----END RSA PRIVATE KEY-----"].join("\n"), // pragma: allowlist secret
  // Checksum-valid Visa-prefixed PAN (classic test number) and a near-miss
  visaPan: "4111" + "1111" + "1111" + "1111",
  visaPanInvalid: "4111" + "1111" + "1111" + "1112",
};

// Sanity: anthropic body must be exactly 93 chars between "api03-" and "AA".
const anthropicBody = FAKE.anthropicKey.slice("sk-ant-api03-".length, -2);
if (anthropicBody.length !== 93) {
  throw new Error(`fixture bug: anthropic body is ${anthropicBody.length} chars, expected 93`);
}
