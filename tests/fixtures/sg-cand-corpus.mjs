// Texts for the pin of the sg-cand-1 generator (tests/verifier/generator.test.ts):
// every form its rules read, the gates it keeps and the flags it records, long
// lines, CRLF, surrogate pairs, values over two lines. Plain JavaScript, so that
// the frozen generator (scripts/rule-candidates.mjs at 4e93cfa) can be run on
// the same texts. Every value is FAKE and built by concatenation: no
// token-shaped literal stands in this file.
const v = (...parts) => parts.join("");
const A = v("kQ9zX2mP7v", "B4wL8nR3tY", "6hG5jD1fC0");
const B = v("Qm7", "xR2", "pL9", "vN4", "kT8");
const C = v("Zx9", "!kLm2#", "Qw8rT5yU");
const pem = [v("-----BEGIN RSA ", "PRIVATE KEY-----"), v("MIIEkQ9zX2mP7vB4wL8nR3tY6hG5jD1fC0aSeUiO".repeat(2), "=="), v("-----END RSA ", "PRIVATE KEY-----")].join("\n");
const jwt = v("eyJhbGciOiJIUzI1NiJ9", ".", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", ".", "kQ9zX2mP7vB4wL8nR3tY6hG5jD1fC0aSeUiO");

export const CORPUS = [
  [
    "app/config.env",
    [
      `DB_PASS=${B}w`,
      `export MYSQL_PWD=${B}`,
      `SMTP_PASS=${B}`,
      `api_key = "${A}"`,
      `"db_pass": "${B}"`,
      `admin_pass = "${C}"`,
      `secret: \\"${A}\\"`,
      `token => '${B}x'`,
      `auth_token == \`${A}\``,
      `password != "changeme"`,
      `apiKey: [${A}]`,
      `settings['client_secret'] = "${A}"`,
      `Authorization: Bearer ${A}${A}`,
      `curl -H "Authorization: Basic ${v("dXNlcjpw", "YXNzd29yZA==")}"`,
      `token: Bearer abc`,
      `password = "${v("pass", "word")}"`,
      `pwd = "/private/var/folders/x/T/dir"`,
      `public_key = "${A}"`,
      `fingerprint_api_key = "${A}"`,
      `aws_access_key_id = ${v("AKIA", "Q7R2M3XBL4WPZ6TK")}`,
      `aws_access_key_id = ${v("AKIA", "Q7R2M3XBLEXAMPLE")}`,
      `card ${v("4111", "1111", "1111", "1111")} and ${v("4111", "1111", "1111", "1112")}`,
      `postgres://admin:${B}@db.internal:5432/app`,
      `postgres://postgres:postgres@localhost/app`,
      `github = ${v("ghp_", "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0dF6hJ9")}`,
      `github_doc = ${v("ghp_", "aB3dE6gH9jK2mN5p", "00000000", "vW4yZ7bC0dF6")}`,
      `jwt=${jwt}`,
      `key = "${A}" // gitleaks:allow`,
      `# pragma: allowlist nextline secret`,
      `secret_key = "${A}"`,
      `token = "\${SECRET_TOKEN}"`,
      `passwd = "xxxxxxxx"`,
      `nonce=${v("a1b2", "c3d4", "e5f6")}`,
      `salt: ${v("9f8e", "7d6c", "5b4a")}`,
      `password: SECRETGATE_0123456789ab`,
      `cred=${B}\r`,
      `pässwörd = "${v("Grüß", "Gott", "123!")}"`,
      `emoji_token = "${v("\u{1F511}", A)}"`,
      `long ${"x".repeat(1200)} api_key="${A}" ${"y".repeat(900)}`,
    ].join("\n"),
  ],
  ["keys/id_rsa.txt", `-- a key over several lines --\n${pem}\nafter`],
  ["package-lock.json", `{"name":"x","integrity":"sha512-${A}","api_key":"${A}"}`],
  ["src/test/fixtures/sample.yaml", `password: ${B}\nsecret_token: ${A}\n`],
  [null, `no path here: token=${B} and Bearer ${A}${B}`],
  [null, ""],
  [null, "keykeykey".repeat(30)],
];
