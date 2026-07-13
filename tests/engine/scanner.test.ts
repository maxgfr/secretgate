import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { scan } from "../../src/engine/scanner.js";
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
});

describe("scan — dedupe", () => {
  it("emits a single finding when a specific rule and generic-api-key overlap", () => {
    const findings = scan(`key = ${FAKE.awsKeyId}`);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe("aws-access-token");
  });
});
