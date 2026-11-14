import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { RULES } from "../../src/engine/rules.gen.js";
import { isNonSecret, nameTrustingKeywords, rulePatterns, ScanBudgetError, scan, sensitiveFileNameRule } from "../../src/engine/scanner.js";
import { FAKE } from "../fixtures/fake-tokens.js";

const sha256hex = (s: string) => createHash("sha256").update(s).digest("hex");

describe("scan — detection", () => {
  it("finds an AWS access key id with rule id, secret and exact span", () => {
    const text = `config:\n  key: ${FAKE.awsKeyId}\n`;
    const findings = scan(text);
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.ruleId).toBe("aws-access-token");
    expect(f.secret).toBe(FAKE.awsKeyId);
    expect(text.slice(f.start, f.end)).toBe(FAKE.awsKeyId);
    expect(f.line).toBe(1);
  });

  it("finds a GitHub PAT, an Anthropic key, a Slack bot token and a private key", () => {
    for (const [rule, token] of [
      ["github-pat", FAKE.githubPat],
      ["anthropic-api-key", FAKE.anthropicKey],
      ["slack-bot-token", FAKE.slackBotToken],
      ["private-key", FAKE.privateKey],
    ] as const) {
      const findings = scan(`some text before\n${token}\nafter`);
      expect(
        findings.map((f) => f.ruleId),
        rule,
      ).toContain(rule);
    }
  });

  it("reports multiple findings in one payload", () => {
    const findings = scan(`a=${FAKE.awsKeyId}\nb=${FAKE.githubPat}`);
    expect(findings.map((f) => f.ruleId).sort()).toEqual(["aws-access-token", "github-pat"]);
  });

  it("enforces the entropy gate (low-entropy candidate is not a finding)", () => {
    const findings = scan('api_key = "aaaaaaaaaaaaaaaaaaaa"');
    expect(findings).toEqual([]);
  });

  it("honors upstream stopword allowlists (generic-api-key skips example-ish values)", () => {
    const findings = scan('api_key = "3xample_s3cret_value_9k2q"'.replace("3xample", "example"));
    expect(findings.filter((f) => f.ruleId === "generic-api-key")).toEqual([]);
  });

  it("detects a generic high-entropy secret in assignment context", () => {
    const findings = scan(`token = "${FAKE.genericSecret}"`);
    expect(findings.map((f) => f.ruleId)).toContain("generic-api-key");
  });

  it("does NOT flag prose without secret-shaped content", () => {
    expect(scan("Please refactor the parser and add tests for the edge cases.")).toEqual([]);
  });
});

describe("scan — suppression", () => {
  it("suppresses findings on gitleaks:allow lines", () => {
    expect(scan(`key = ${FAKE.awsKeyId} # gitleaks:allow`)).toEqual([]);
  });

  it("suppresses findings under pragma allowlist nextline", () => {
    expect(scan(`# pragma: allowlist nextline secret\nkey = ${FAKE.awsKeyId}`)).toEqual([]);
  });

  it("suppresses values allowlisted by hash", () => {
    const findings = scan(`key = ${FAKE.awsKeyId}`, { allowlist: { sha256: [sha256hex(FAKE.awsKeyId)] } });
    expect(findings).toEqual([]);
  });

  it("suppresses disabled rule ids but keeps others", () => {
    const findings = scan(`a=${FAKE.awsKeyId}\nb=${FAKE.githubPat}`, { allowlist: { rules: ["aws-access-token"] } });
    expect(findings.map((f) => f.ruleId)).toEqual(["github-pat"]);
  });

  it("suppresses everything for user-allowlisted path globs", () => {
    const findings = scan(`key = ${FAKE.awsKeyId}`, { sourcePath: "tests/fixtures/sample.txt", allowlist: { paths: ["tests/fixtures/**"] } });
    expect(findings).toEqual([]);
  });

  it("suppresses everything for upstream global-allowlist paths (lockfiles etc.)", () => {
    const findings = scan(`key = ${FAKE.awsKeyId}`, { sourcePath: "some/dir/package-lock.json" });
    expect(findings).toEqual([]);
  });
});

describe("scan — credit cards (Luhn + IIN gated)", () => {
  it("flags a checksum-valid Visa-prefixed number", () => {
    const findings = scan(`card: ${FAKE.visaPan}`);
    expect(findings.map((f) => f.ruleId)).toContain("credit-card-number");
  });

  it("ignores a checksum-invalid number and non-card digit runs", () => {
    expect(scan(`card: ${FAKE.visaPanInvalid}`)).toEqual([]);
    expect(scan("build id: 1234567890123456")).toEqual([]);
  });

  // Measured on a 42k-file corpus: 231 of 250 card "findings" were SVG path and
  // ellipse coordinates, the rest geo fixtures. A long fraction has ~1/10 odds
  // of satisfying Luhn, and vector art emits thousands of them. A PAN is never
  // written immediately after a decimal point, so the dot settles it.
  it("ignores digit runs that are the fractional part of a decimal", () => {
    for (const text of [
      `<ellipse rx="0.${FAKE.visaPan}" />`,
      `coordinates: [-73.${FAKE.visaPan}, 40.7]`,
      `scale = 1.${FAKE.visaPan}`,
      `amount = ${FAKE.visaPan}.25`,
    ]) {
      expect(
        scan(text).filter((f) => f.ruleId === "credit-card-number"),
        text,
      ).toEqual([]);
    }
  });

  it("still flags a PAN next to punctuation that is not a decimal point", () => {
    for (const text of [`card=${FAKE.visaPan};`, `{"pan":"${FAKE.visaPan}"}`, `(${FAKE.visaPan})`, `card: ${FAKE.visaPan}.`]) {
      expect(
        scan(text).map((f) => f.ruleId),
        text,
      ).toContain("credit-card-number");
    }
  });
});

// Credentials a coding agent's .env commonly holds and gitleaks ships no rule
// for: measured by feeding each one alone to both engines.
describe("scan — AI-provider keys and webhooks (secretgate builtin)", () => {
  it("has fixtures of the documented lengths", () => {
    expect(FAKE.groqKey.length).toBe(4 + 52);
    expect(FAKE.replicateToken.length).toBe(3 + 37);
    expect(FAKE.xaiKey.length).toBe(4 + 80);
    expect(FAKE.discordWebhook.split("/").at(-1)!.length).toBe(68);
  });

  for (const [rule, bare, text, secret] of [
    ["groq-api-key", FAKE.groqKey, `GROQ_API_KEY=${FAKE.groqKey}`, FAKE.groqKey],
    ["replicate-api-token", FAKE.replicateToken, `export REPLICATE_API_TOKEN="${FAKE.replicateToken}"`, FAKE.replicateToken],
    ["xai-api-key", FAKE.xaiKey, `client = Client(api_key="${FAKE.xaiKey}")`, FAKE.xaiKey],
    ["discord-webhook-url", FAKE.discordWebhook, `curl -X POST ${FAKE.discordWebhook} -d '{}'`, FAKE.discordWebhook.split("/").at(-1)!],
  ] as const) {
    it(`finds a ${rule} on its own and in context`, () => {
      for (const t of [bare, text]) {
        const f = scan(t).find((x) => x.ruleId === rule);
        expect(f, t).toBeDefined();
        expect(f!.secret).toBe(secret);
      }
    });
  }

  it("ignores low-entropy and truncated look-alikes", () => {
    for (const text of [
      `gsk_${"x".repeat(52)}`,
      "gsk_short",
      `r8_${"0".repeat(37)}`,
      `xai-${"a".repeat(80)}`,
      "https://discord.com/api/webhooks/1203948576102938475/abc",
      "see https://discord.com/developers/docs/resources/webhook",
    ]) {
      expect(
        scan(text).filter((f) => ["groq-api-key", "replicate-api-token", "xai-api-key", "discord-webhook-url"].includes(f.ruleId)),
        text,
      ).toEqual([]);
    }
  });
});

describe("scan — url credentials (secretgate builtin)", () => {
  const cases: Array<[string, string]> = [
    ["postgres", "DATABASE_URL=postgres://admin:Xk9mQ2vL7pR4tY6h@db:5432/prod"],
    ["redis (no user)", "redis://:Xk9mQ2vL7pR4tY6hN3@cache:6379"],
    ["mongodb+srv", "mongodb+srv://dbadmin:Xk9mQ2vL7pR4tY6h@cluster0.mongodb.net"],
    ["https basic-auth", "clone https://svc:Xk9mQ2vL7pR4tY6hZ8@api.internal.co/v1"],
  ];
  for (const [name, text] of cases) {
    it(`catches an embedded credential (${name})`, () => {
      expect(scan(text).map((f) => f.ruleId)).toContain("url-credentials");
    });
  }

  it("does not flag placeholder/masked/interpolated/port URLs", () => {
    // biome-ignore lint/suspicious/noTemplateCurlyInString: literal interpolation syntax is the test input.
    for (const text of ["postgres://user:password@localhost/db", "https://user:****@host", "postgres://user:${DB_PASS}@host", "http://localhost:8080/path"]) {
      expect(
        scan(text).filter((f) => f.ruleId === "url-credentials"),
        text,
      ).toEqual([]);
    }
  });

  // 44 of 196 URL-credential findings on the corpus repeated the username or
  // the scheme as the password — the canonical docker-compose / tutorial string.
  // A deployment where the password IS the username is not a secret worth
  // blocking a prompt over.
  it("does not flag a password that repeats the username or the scheme", () => {
    for (const text of [
      "postgresql://postgres:postgres@localhost:5432/db",
      "mysql://root:root@mysql/airflow",
      "amqp://rabbitmq:rabbitmq@broker:5672",
      "mongodb://mongo:mongodb@cluster/db",
    ]) {
      expect(
        scan(text).filter((f) => f.ruleId === "url-credentials"),
        text,
      ).toEqual([]);
    }
  });

  it("still flags a real password that merely starts like the username", () => {
    for (const text of ["postgres://postgres:postgres_9xKqW3zR@db/prod", "mysql://root:rootKQ92mZ7v@db/prod"]) {
      expect(
        scan(text).map((f) => f.ruleId),
        text,
      ).toContain("url-credentials");
    }
  });
});

describe("scan — quoted password assignment (secretgate builtin)", () => {
  it("catches a quoted password with punctuation that generic-api-key misses", () => {
    expect(scan('password = "Xq9$mK2vLp7wRt4z"').map((f) => f.ruleId)).toContain("password-assignment");
    expect(scan('{"api_key": "sk_Xq9mK2vLp7wRt4zN8"}').map((f) => f.ruleId)).toContain("password-assignment");
  });

  // 155 of 649 password-assignment findings on the corpus held whitespace, and
  // every sampled one was a UI label or a sentence — Airflow's connection forms
  // relabel their fields, so `"password"` routinely carries "Client Secret".
  it("does NOT fire on values containing whitespace (labels and prose)", () => {
    for (const text of [
      '"relabeling": {"login": "Client ID", "password": "Client Secret"}',
      'RESOURCE_MY_PASSWORD = "My Password"',
      'api_key = "Enter your key in the settings page"',
    ]) {
      expect(
        scan(text).filter((f) => f.ruleId === "password-assignment"),
        text,
      ).toEqual([]);
    }
  });

  // A value that is entirely an interpolation is a REFERENCE to a secret. The
  // bare `${VAR}` form was already covered; the property-access form is what
  // every bundled JS file looks like (`apikey: ${this.supabaseKey}`).
  it("skips values that are entirely an interpolation or template reference", () => {
    for (const text of [
      // biome-ignore lint/suspicious/noTemplateCurlyInString: literal interpolation syntax is the test input.
      "let p = { apikey: `${this.supabaseKey}` };",
      // biome-ignore lint/suspicious/noTemplateCurlyInString: literal interpolation syntax is the test input.
      'api_key = "${config.apiKey}"',
      // biome-ignore lint/suspicious/noTemplateCurlyInString: literal interpolation syntax is the test input.
      'password = "${env:DB_PASSWORD}"',
      'password = "%(db_password)s"',
      'secret = "{settings.api_key}"',
      'client_secret = "$(cat /run/secrets/client_secret)"',
      "access_key = \"#{ENV['AWS_ACCESS_KEY']}\"",
      'password = "<%= node[:db][:password] %>"',
    ]) {
      expect(
        scan(text).filter((f) => f.ruleId === "password-assignment"),
        text,
      ).toEqual([]);
    }
  });

  // The interpolation guard must stay anchored: a secret that merely CONTAINS
  // `$`, `{` or `%` is still a secret.
  it("still flags secrets that merely contain interpolation characters", () => {
    for (const text of ['password = "P@ss{w0rd}$9xKq"', 'api_key = "aB3$dE6gH9jK2mN5pQ8"', 'secret = "x%2Fy%2Bz9QwErTy"']) {
      expect(scan(text).filter((f) => f.ruleId === "password-assignment").length, text).toBeGreaterThan(0);
    }
  });

  it("does NOT fire on ordinary code (unquoted expressions)", () => {
    for (const code of ["if (secret === undefined) return x;", "const apiKey = getKey();", "const password = req.body.password;", "let pwd = user.pwd"]) {
      expect(
        scan(code).filter((f) => f.ruleId === "password-assignment"),
        code,
      ).toEqual([]);
    }
  });

  it("skips placeholder passwords", () => {
    for (const text of ['password = "changeme"', 'password: "hunter2"', 'password = "example"']) {
      expect(
        scan(text).filter((f) => f.ruleId === "password-assignment"),
        text,
      ).toEqual([]);
    }
  });

  // `pwd` is in the keyword set as an abbreviation for "password", but on a
  // developer machine it is far more often POSIX print-working-directory. Go
  // test output of the form `pwd = "/private/var/folders/..."` is long and
  // mixed-case enough to clear the entropy gate, so it was being redacted
  // mid-run -- corrupting the very diagnostics the user was reading.
  it("skips filesystem paths assigned to secret-ish keywords", () => {
    for (const text of [
      'pwd = "/private/var/folders/pz/tpqs6qkx41sdm04rm630llhm0000gn/T/TestRunGuard_WorkingDirectory4169563585/001"',
      'pwd = "/Users/maxime/Library/Caches/some-tool/artifacts"',
      'secret_key = "./config/secrets/production.key"',
      'key: "~/.ssh/id_ed25519"',
      'api_key = "../../vendor/github.com/foo/bar"',
      'password = "C:\\\\Users\\\\maxime\\\\AppData\\\\Local\\\\Temp"',
    ]) {
      expect(
        scan(text).filter((f) => f.ruleId === "password-assignment"),
        text,
      ).toEqual([]);
    }
  });

  // The path guard must stay narrow: a path root, >=2 separators AND a
  // punctuation-free charset are all required. Slashes alone buy no exemption.
  it("still flags real secrets that resemble paths", () => {
    for (const text of [
      'password = "aGVsbG8vd29ybGQrZm9vL2Jhcg=="',
      'password = "abc/def/ghi/jkl/mno/pqr"',
      'password = "/Xk92mfPqLzT4vBn"',
      'password = "/tmp/xQz42Kp9!@#$"',
    ]) {
      expect(scan(text).filter((f) => f.ruleId === "password-assignment").length, text).toBeGreaterThan(0);
    }
  });

  // PLACEHOLDER_WORDS is rule-independent: a vendor rule must not re-flag what
  // the placeholder list already declared inert.
  it("skips placeholder values for EVERY rule, not just password-assignment", () => {
    for (const text of ['password = "changeme"', 'resource "x" { password = "changeme" }', 'password = "example"', 'password = "test"']) {
      expect(scan(text), text).toEqual([]);
    }
  });
});

describe("scan — wall-clock budget (anti-hang)", () => {
  it("throws ScanBudgetError when the deadline is already past", () => {
    // deadlineMs 0 -> the between-rule check trips on the first rule
    expect(() => scan(`some text with a key = ${FAKE.githubPat}`, { deadlineMs: 0 })).toThrow(ScanBudgetError);
  });

  it("does not throw for a normal payload within a generous budget", () => {
    expect(() => scan(`key = ${FAKE.githubPat}`, { deadlineMs: 5000 })).not.toThrow();
  });

  it("has no budget by default (offline CLI scan may take its time)", () => {
    expect(() => scan(`key = ${FAKE.githubPat}`)).not.toThrow();
  });
});

// A false redaction costs almost nothing here (the value is restored
// locally); a miss is a leak. So a value is dropped only when the text makes
// it structurally certain that it is public or not a credential: its own name
// says so, it is its own variable name, or it carries a documented public
// prefix. What a value merely LOOKS like decides nothing.
describe("scan — a value is dropped only when the text makes it certain", () => {
  const none = (texts: string[]) => {
    for (const text of texts) expect(scan(text), text).toEqual([]);
  };
  const some = (texts: string[]) => {
    for (const text of texts) expect(scan(text).length, text).toBeGreaterThan(0);
  };

  // These were dropped for a while, on the look of the value alone. Each is a
  // password or a key somebody may really have.
  it("flags a value made of dictionary words, partly masked, or ending in EXAMPLE", () => {
    const upper = FAKE.genericSecret.toUpperCase();
    some([
      'DB_PASSWORD="MySuperSecretPassword"',
      'password = "TopSecretAdminPassword"',
      "headers: { 'X-TOKEN-SECRET': 'SuperSecretToken' },",
      'secret = "your-api-key-here"',
      `postgres://app:${"SuperSecret" + "Password"}@db.internal:5432/app`,
      'password = "Tr0ub4dor****x9Qz"',
      `postgres://app:${"hunter****" + "9Xq"}@db.internal/app`,
      `api_key = "${upper}EXAMPLE"`,
      'secret = "Q7R2M3XB4WPZ6TK' + 'EXAMPLE"',
    ]);
    expect(scan(`token ${"ghp_" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC" + "EXAMPLE"}`).map((f) => f.ruleId)).toEqual(["github-pat"]);
    // What upstream documents stays: AWS's own example key id, and the base placeholders.
    none([`aws_access_key_id = ${"AKIA" + "IOSFODNN7" + "EXAMPLE"}`, 'password = "changeme"', 'password = "********"']);
  });

  it("skips a value that only restates the name it is assigned to", () => {
    none(["var obj1KeysLength = obj1Keys.length;", "const apiKeyHeader = api_key_header;", "export const SESSION_TOKEN_NAME = 'session-token-name';"]);
    some([`var obj1KeysLength = ${FAKE.genericSecret};`, `const apiKeyHeader = "${FAKE.genericSecret}";`]);
  });

  // The one name that exempts a value is the one that SAYS it is public. A
  // "cache key" or a "fingerprint" describes a role; nothing in it says the
  // value may be shown (an HMAC key for a cache is a `cache_key` too).
  it("skips what its own name calls a public key", () => {
    const b64 = "pL1+qb9HTMRZJmuC/bB/ZI" + "9d302BYrrqiVuRyW+DGrU=";
    none([
      ` *   Public key ping-sha256: ${b64}`,
      `public key: ${FAKE.genericSecret}`,
      `ssh_public_key = "${FAKE.genericSecret}"`,
      `PUBKEY=${FAKE.genericSecret}`,
    ]);
    // The label must be the value's own: a neighbour's does not count.
    some([`{"public_key": "abc", "private_key": "${FAKE.genericSecret}"}`, `the public key is known, the api key: ${FAKE.genericSecret}`]);
  });

  it("flags what a name calls a cache key or a fingerprint: neither says public", () => {
    const hex40 = "9554f04d7259f04124de" + "6b476d5a82ac7e37093b";
    some([
      `cache_key = "${FAKE.genericSecret}"`,
      `      - CACHE_KEY=${hex40}`,
      `cache_key_hmac = "${FAKE.genericSecret}"`,
      `cache_key_salt = "${FAKE.genericSecret}"`,
      `api_cache_key = "${FAKE.genericSecret}"`,
      `session_cache_key = "${FAKE.genericSecret}"`,
      `cache_keys = "${FAKE.genericSecret}"`,
      `mysql cache_key: ${FAKE.genericSecret}`,
      `key_fingerprint = "${hex40.slice(0, 32)}"`,
      `- Release GPG key: ${hex40.toUpperCase()}`,
    ]);
  });

  // Every word a name-trusting rule fires on names a credential: next to it,
  // "public key" exempts nothing. The list is the rules' own, so it cannot
  // fall behind them — `pwd` was missing from a hand-written copy.
  it("takes the exemption back for every keyword of the rules that trust a name", () => {
    const keywords = nameTrustingKeywords();
    for (const k of ["pwd", "password", "passwd", "secret", "token", "key", "api", "auth", "access", "credential", "creds"]) expect(keywords, k).toContain(k);
    for (const k of keywords) {
      for (const text of [`public key ${k}: ${FAKE.genericSecret}`, `${k} public key: ${FAKE.genericSecret}`])
        expect(scan(text).length, text).toBeGreaterThan(0);
    }
    some([
      `cache_key_pwd = "${FAKE.genericSecret}"`,
      `fingerprint_pwd = "${FAKE.genericSecret}"`,
      `public_key_pwd = "${FAKE.genericSecret}"`,
      `public key pwd = "${FAKE.genericSecret}"`,
      `CACHE_KEY_PWD=${FAKE.genericSecret}`,
      `cache-key-pwd: ${FAKE.genericSecret}`,
      `public_key_secret = "${FAKE.genericSecret}"`,
      `public_keystore_password = "${FAKE.genericSecret}"`,
    ]);
  });

  // A word the rules match on without it being a keyword would escape the
  // list above: each alternative of their name patterns must hold one.
  it("knows every word the name patterns match as a keyword", () => {
    const keywords = nameTrustingKeywords();
    for (const id of ["generic-api-key", "password-assignment"]) {
      const source = rulePatterns().find((r) => r.id === id)!.re.source;
      // The group of alternatives that holds "secret": the names the rule fires on.
      const at = source.indexOf("secret");
      let open = at;
      for (let depth = 0; ; open--) {
        if (source[open] === ")") depth++;
        else if (source[open] === "(" && depth-- === 0) break;
      }
      const alternatives: string[] = [""];
      for (let i = open + 3, depth = 0; depth >= 0; i++) {
        const c = source[i]!;
        if (c === "(") depth++;
        if (c === ")") depth--;
        if (c === "|" && depth === 0) alternatives.push("");
        else if (depth >= 0) alternatives[alternatives.length - 1] += c;
      }
      const words = alternatives.map((w) =>
        w
          .replace(/\(\?:[^()]*\)\?/g, "")
          .replace(/\[[^\]]*\]\??/g, "")
          .replace(/[^a-z]/gi, "")
          .toLowerCase(),
      );
      expect(words.length, id).toBeGreaterThan(5);
      expect(words, id).toContain("secret");
      for (const word of words)
        expect(
          keywords.some((k) => word.includes(k)),
          `${id}: ${word}`,
        ).toBe(true);
    }
  });

  it("skips a Stripe publishable key under a name that says public, and nowhere else", () => {
    const body = FAKE.genericSecret + FAKE.genericSecret;
    none([`stripe_publishable_key = pk_test_${body}`, `      - NEXT_PUBLIC_STRIPE_KEY=pk_live_${body}`, `\tstripePublishableKey := "pk_live_${body}"`]);
    expect(scan(`stripe_key = sk_live_${body}`).map((f) => f.ruleId)).toEqual(["stripe-access-token"]);
    some([
      // The prefix alone proves nothing: the name has to agree, and to hold no credential word.
      `api_key = "pk_live_${body}"`,
      `secret_key = "pk_live_${body}"`,
      `STRIPE_SECRET_KEY=pk_live_${body}`,
      `password = "pk_test_${body}"`,
      `stripe_key = pk_live_${body}`,
      `public_secret_key = pk_live_${body}`,
      // The whole value has to be a publishable key, not merely to start like one.
      `stripe_publishable_key = pk_prod_${body}`,
      `stripe_publishable_key = "xpk_test_${body}"`,
      `stripe_publishable_key = pk_live_${body}.${FAKE.genericSecret}`,
    ]);
  });

  it("skips a GitHub token no generator would produce: one character eight times in a row", () => {
    none([
      `const auth = createTokenAuth("${"ghp_" + "PersonalAccessToken0124567890" + "0000000"}");`,
      `//   token: '${"ghs_" + "InstallallationOrActionToken" + "00000000"}',`,
      `createTokenAuth("${"ghu_" + "InstallationUserToServer" + "000000000000"}");`,
    ]);
    // Seven in a row can still be drawn; and the rule is GitHub's alone.
    expect(scan(`TOKEN=${"ghp_" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC" + "0000000"}`).map((f) => f.ruleId)).toEqual(["github-pat"]);
    expect(scan(`TOKEN=${FAKE.githubPat}`).map((f) => f.ruleId)).toEqual(["github-pat"]);
    some([`password = "Xq9$mK2vLp7wRt4z${"0".repeat(8)}"`]);
  });
});

// Text that secretgate redacted must not be flagged again. That exemption is
// for its OWN placeholder, exactly, give or take punctuation: anything else
// written around one is material like any other.
describe("scan — its own placeholders", () => {
  const placeholder = "SECRETGATE_" + "0123456789ab";

  it("leaves a placeholder alone, bare or next to a separator or two", () => {
    const other = "SECRETGATE_" + "ba9876543210";
    for (const text of [
      `password = "${placeholder}"`,
      `token: ${placeholder}.`,
      `key=${placeholder}=`,
      `secret_key = ${placeholder}__`,
      `password = "${placeholder}-${other}"`,
      `password = "${placeholder}.${other}."`,
      `api_key = "${placeholder}${other}"`,
    ]) {
      expect(scan(text), text).toEqual([]);
    }
  });

  // The allowance is for the separator a wider rule takes with a token, not
  // for a password made of symbols: a few separator characters, no more.
  it("flags symbols around a placeholder beyond a separator or two", () => {
    const other = "SECRETGATE_" + "ba9876543210";
    for (const text of [
      `password = "${placeholder}!@#$%^&*()"`,
      `password = "${placeholder}!@#$%^&*${other}"`,
      `secret = "${placeholder}!"`,
      `password = "${placeholder}....----"`,
      `password = "~${placeholder}~"`,
    ]) {
      expect(
        scan(text).map((f) => f.ruleId),
        text,
      ).toEqual(["password-assignment"]);
    }
  });

  it("flags letters or digits written around a placeholder: a forged one hides nothing", () => {
    for (const text of [
      `password = "${placeholder}X9q!z"`,
      `password = "X9q!z${placeholder}"`,
      `password = "${placeholder}:pass1"`,
      // Hex right after it: a 12-digit placeholder does not swallow what follows.
      `password = "${placeholder}beef"`,
      `password = "${placeholder}cafe!"`,
      `api_key = "${placeholder}0f9a3c7e1b"`,
    ]) {
      const found = scan(text);
      expect(
        found.map((f) => f.ruleId),
        text,
      ).toEqual(["password-assignment"]);
      expect(found[0]!.secret, text).toBe(text.slice(text.indexOf('"') + 1, -1));
    }
  });
});

// An AWS access key id comes with a secret access key, and in a credentials
// CSV (`Access key ID,Secret access key`) nothing names the second: the row
// is `<key id>,<secret key>`. That pair is detected for what it is. Nothing
// wider: what follows any other token, or a placeholder, is not a credential
// for standing there.
describe("scan — the AWS secret access key next to its key id", () => {
  const awsSecret = "wJalrXUtnFEMI" + "/K7MDENG/" + "bPxRfiCYzQ9kT4mB2x";
  const placeholder = "SECRETGATE_" + "0123456789ab";
  const sha = "3f786850e387550fdab8" + "36ed7e6dc881de23001b";
  const rules = (text: string) => scan(text, { pragmas: false }).map((f) => f.ruleId);

  it("flags the 40 characters that follow a key id after `,` or `:`", () => {
    for (const text of [
      `Access key ID,Secret access key\n${FAKE.awsKeyId},${awsSecret}\n`,
      `"${FAKE.awsKeyId}","${awsSecret}"`,
      `${FAKE.awsKeyId}:${awsSecret}`,
      `user,${FAKE.awsKeyId}, ${awsSecret},eu-west-1`,
    ]) {
      const found = scan(text);
      expect(
        found.map((f) => f.ruleId),
        text,
      ).toEqual(["aws-access-token", "aws-secret-access-key"]);
      expect(text.slice(found[1]!.start, found[1]!.end)).toBe(awsSecret);
    }
  });

  it("flags nothing else that follows a key id", () => {
    for (const text of [
      `${FAKE.awsKeyId},${sha}`, // a hex digest
      `${FAKE.awsKeyId},${awsSecret.slice(0, 39)}`, // not 40 characters
      `${FAKE.awsKeyId},${awsSecret}A`,
      `${FAKE.awsKeyId},request_id=req_8f3a2b1c9d4e5f60aaaaaaaaaaaaaaaa`,
      `${FAKE.awsKeyId}: report-2026-11-14_final.v2.pdf`,
      `${FAKE.awsKeyId}, BUILD=2026.11.14-r7xQ9z1`,
      `${FAKE.awsKeyId},550e8400-e29b-41d4-a716-446655440000`,
      `${FAKE.awsKeyId} ${awsSecret}`, // a space is not a separator
      `${FAKE.awsKeyId}\n${awsSecret}`,
      `${FAKE.awsKeyId},${"a".repeat(20)}${"b".repeat(20)}`, // no entropy
    ]) {
      expect(rules(text), text).toEqual(["aws-access-token"]);
    }
  });

  // These ended sessions: after a placeholder (or any token), each was taken
  // for the other half of a credential.
  it("takes nothing for a credential because it follows a placeholder or another token", () => {
    for (const text of [
      `${placeholder},${sha}`,
      `${placeholder}: report-2026-11-14_final.v2.pdf`,
      `+ export TOKEN=${placeholder}, BUILD=2026.11.14-r7xQ9z1`,
      `token=${placeholder},request_id=req_8f3a2b1c9d4e5f60`,
      `${placeholder}: v1.2.3-beta.4+build.5678ab`,
      `${placeholder},${awsSecret}`,
      `["${placeholder}","${sha}","${sha.slice(0, 30)}abcdef"]`,
    ]) {
      expect(rules(text), text).toEqual([]);
    }
    expect(rules(`${FAKE.githubPat},${sha},${sha}`)).toEqual(["github-pat"]);
    expect(rules(`token=${FAKE.githubPat},request_id=req_8f3a2b1c9d4e5f60,user=42`)).toEqual(["github-pat"]);
  });

  // The placeholder's text holds the word "secret", a keyword of the generic
  // rule: `SECRETGATE_….id = value` matched it as a NAME.
  it("never takes a placeholder's own text for a credential-sounding name", () => {
    expect(rules(`${placeholder}.id = ${FAKE.genericSecret}`)).toEqual([]);
    expect(rules(`x${placeholder} retries: ${FAKE.genericSecret}`)).toEqual([]);
    expect(rules(`${placeholder}: ${FAKE.genericSecret}`)).toEqual([]);
  });

  it("can be switched off like any rule", () => {
    expect(scan(`${FAKE.awsKeyId},${awsSecret}`, { allowlist: { rules: ["aws-secret-access-key"] } }).map((f) => f.ruleId)).toEqual(["aws-access-token"]);
  });
});

describe("scan — dedupe", () => {
  it("emits a single finding when a specific rule and generic-api-key overlap", () => {
    const findings = scan(`key = ${FAKE.awsKeyId}`);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe("aws-access-token");
  });

  // A quoted value that holds a vendor token AND other secret material: the
  // vendor rule sees the token, password-assignment sees the whole value. The
  // narrower finding used to win, so the rest of the value was never redacted.
  it("keeps the wider finding when a vendor token is only part of a flagged value", () => {
    const rest = "wJalrXUtnFEMI" + "K7MDENGbPxRfiCY" + "zQ9kT4mB2x";
    for (const value of [`${FAKE.awsKeyId}:${rest}`, `${rest}:${FAKE.awsKeyId}`, `${rest}:${FAKE.awsKeyId}:${rest}`]) {
      const text = `api_key = "${value}"`;
      const findings = scan(text);
      expect(findings, value).toHaveLength(1);
      expect(findings[0]!.secret, value).toBe(value);
      expect(text.slice(findings[0]!.start, findings[0]!.end), value).toBe(value);
    }
  });

  it("keeps the wider finding as soon as a letter or a digit stands outside the vendor token", () => {
    for (const extra of [":1234", ":a1B2c", "-x"]) {
      const text = `auth_token = "${FAKE.githubPat}${extra}"`;
      const findings = scan(text);
      expect(findings, extra).toHaveLength(1);
      expect(findings[0]!.secret, extra).toBe(`${FAKE.githubPat}${extra}`);
    }
  });

  it("still prefers the vendor rule when the wider finding adds nothing but punctuation", () => {
    // generic-api-key also captures the trailing dot; the token alone is the secret.
    const findings = scan(`TOKEN=${FAKE.githubPat}.\n`);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe("github-pat");
    expect(findings[0]!.secret).toBe(FAKE.githubPat);
  });

  it("covers both spans when two findings overlap without one containing the other", () => {
    // The URL password runs past the quote that ends the assigned value.
    const [head, tail] = ["kQ9zX2mP7v", "B4wL8nR3tY"];
    const text = `secret="amqp://svc:${head}"${tail}@mq.internal`;
    const findings = scan(text);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.secret).toBe(`amqp://svc:${head}"${tail}`);
    expect(text.slice(findings[0]!.start, findings[0]!.end)).toBe(findings[0]!.secret);
    expect(findings[0]!.ruleId).toBe("url-credentials");
  });
});

describe("scan — never flags its own rule database", () => {
  // Several rule regexes embed literal secret-shaped constants (e.g. the
  // Bedrock key's base64 prefix), so rendering the rule table as code —
  // gitleaks.toml (raw), rules.gen.ts / the shipped bundles (JSON-escaped) —
  // must not produce findings: pattern text is public by construction.
  it("does not flag any rule regex source rendered raw (gitleaks.toml form)", () => {
    for (const r of RULES) {
      expect(scan(`"source": "${r.regex.source}",`), r.id).toEqual([]);
    }
  });

  it("does not flag any rule regex source rendered JSON-escaped (bundle form)", () => {
    for (const r of RULES) {
      expect(scan(`"source": ${JSON.stringify(r.regex.source)},`), r.id).toEqual([]);
    }
  });

  it("still flags a real secret-shaped token on the same line as rule-source text", () => {
    const findings = scan(`"source": "harmless", "leak": "${FAKE.githubPat}"`);
    expect(findings.map((f) => f.ruleId)).toContain("github-pat");
  });
});

describe("scanner at volume", () => {
  it("scans 5000 distinct tokens in well under a second and keeps them all", () => {
    const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let x = 11;
    const tok = (): string => `ghp${"_"}${Array.from({ length: 36 }, () => ALNUM[(x = (x * 1103515245 + 12345) & 0x7fffffff) % 62]).join("")}`;
    const text = Array.from({ length: 5000 }, (_, i) => `T${i}=${tok()}`).join("\n");
    const started = performance.now();
    const found = scan(text);
    expect(performance.now() - started).toBeLessThan(1000);
    expect(found).toHaveLength(5000);
    expect(found.every((f, i) => i === 0 || f.start >= found[i - 1]!.end)).toBe(true);
  });

  it("names a sensitive file the same way on every call", () => {
    for (let i = 0; i < 3; i++) {
      expect(sensitiveFileNameRule("certs/client.p12")).toBe("pkcs12-file");
      expect(sensitiveFileNameRule("src/index.ts")).toBeUndefined();
    }
  });

  it("never treats a secret as rule text because it spans two rule sources", () => {
    expect(isNonSecret(`${FAKE.githubPat}\u0000x`)).toBe(false);
  });
});
