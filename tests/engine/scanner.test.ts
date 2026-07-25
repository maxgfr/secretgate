import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { RULES } from "../../src/engine/rules.gen.js";
import { ScanBudgetError, scan } from "../../src/engine/scanner.js";
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
      "let p = { apikey: `${this.supabaseKey}` };",
      'api_key = "${config.apiKey}"',
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

describe("scan — dedupe", () => {
  it("emits a single finding when a specific rule and generic-api-key overlap", () => {
    const findings = scan(`key = ${FAKE.awsKeyId}`);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe("aws-access-token");
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
