import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { dedupeFindings, isGloballyAllowedPath, type MatchGate, type ScanConfig, scan, traceMatches } from "../../src/engine/scanner.js";
import { FAKE } from "../fixtures/fake-tokens.js";

// `traceMatches` is the development view of `scan`: every regex match, with the
// gates it fails. The candidate export (scripts/rule-candidates.mjs) is built
// on it, so it has to stay the same loop as `scan`.

const ROOT = join(__dirname, "..", "..");

function* walk(dir: string): Generator<string> {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, e.name);
    if (e.isDirectory()) yield* walk(full);
    else if (e.isFile() && /\.(?:ts|mjs|md|txt|ya?ml|json|toml)$/.test(e.name) && statSync(full).size < 400_000) yield full;
  }
}

const repeated = "a".repeat(8);
// One text per gate, and a few that fail none.
const TEXTS: string[] = [
  `GITHUB_TOKEN=${FAKE.githubPat}\nAWS_ACCESS_KEY_ID=${FAKE.awsKeyId}\n`,
  `api_key = "${FAKE.genericSecret}"`,
  `url = "postgres://admin:Xk9mQ2vL7pR4tY6h@db:5432/prod"`,
  `password = "Zx9!kLm2#Qw8rT5yU"`,
  `card ${FAKE.visaPan} and ${FAKE.visaPanInvalid}`,
  `${FAKE.privateKey}\n`,
  `api_key = "aaaaaaaaaabbbbbbbbbb"`,
  `password = "changeme"\npassword = "correct horse battery"\npwd = "/private/var/folders/pz/T/TestTmpDir/001"`,
  `url = "postgres://postgres:postgres@db:5432/prod"`,
  `key = ${FAKE.awsKeyId} # gitleaks:allow`,
  `# pragma: allowlist nextline secret\nkey = ${FAKE.awsKeyId}`,
  `ssh_public_key = "${FAKE.genericSecret}"`,
  `token: ghp_${repeated}${FAKE.githubPat.slice(12)}`,
  `api_key = "${FAKE.genericSecret.slice(0, 12)}example${FAKE.genericSecret.slice(12)}"`,
  `secret = "$\{DATABASE_SECRET_VALUE}"`,
  `token = "SECRETGATE_0123456789abcdef"`,
  `api_key = "pk_test_${FAKE.genericSecret}"`,
];

const CONFIGS: Array<[string, ScanConfig]> = [
  ["as the hooks scan", { pragmas: false }],
  ["as a file", {}],
  ["with a path", { sourcePath: "config/settings.yml" }],
];

const strip = (text: string, cfg: ScanConfig) =>
  dedupeFindings(
    traceMatches(text, cfg)
      .filter((m) => m.gates.length === 0)
      .map(({ gates: _gates, ...finding }) => finding),
    text,
  );

describe("traceMatches", () => {
  for (const [name, cfg] of CONFIGS) {
    it(`gives back scan's findings from the matches that fail no gate (${name})`, () => {
      for (const text of TEXTS) expect(strip(text, cfg), text.slice(0, 30)).toEqual(scan(text, cfg));
    });
  }

  it("does so on this repository's own sources, tests and fixtures", () => {
    let files = 0;
    let findings = 0;
    for (const dir of ["src", "tests", "docs", "rules"]) {
      for (const file of walk(join(ROOT, dir))) {
        const text = readFileSync(file, "utf8");
        for (const cfg of [{ pragmas: false }, { sourcePath: file.slice(ROOT.length + 1) }]) {
          const expected = scan(text, cfg);
          expect(strip(text, cfg), file).toEqual(expected);
          findings += expected.length;
        }
        files++;
      }
    }
    expect(files).toBeGreaterThan(50);
    expect(findings).toBeGreaterThan(20);
  });

  const gatesOf = (text: string, ruleId: string, cfg: ScanConfig = {}): MatchGate[] => {
    const matches = traceMatches(text, cfg).filter((m) => m.ruleId === ruleId);
    expect(matches, `${ruleId} in ${text.slice(0, 30)}`).toHaveLength(1);
    return matches[0]!.gates;
  };

  it("names the gate a match fails", () => {
    expect(gatesOf(`key = ${FAKE.awsKeyId}`, "aws-access-token")).toEqual([]);
    expect(gatesOf(`api_key = "aaaaaaaaaabbbbbbbbbb"`, "generic-api-key")).toContain("entropy");
    expect(gatesOf(`password = "changeme"`, "password-assignment")).toEqual(["placeholder", "entropy"]);
    expect(gatesOf(`password = "correct horse battery"`, "password-assignment")).toEqual(["post"]);
    expect(gatesOf(`pwd = "/private/var/folders/pz/T/TestTmpDir/001"`, "password-assignment")).toContain("post");
    expect(gatesOf(`url = "postgres://postgres:postgres@db:5432/prod"`, "url-credentials")).toEqual(["post-match"]);
    expect(gatesOf(`url = "postgres://app:changeme@db:5432/prod"`, "url-credentials")).toEqual(["placeholder"]);
    expect(gatesOf(`card ${FAKE.visaPanInvalid}`, "credit-card-number")).toEqual(["post"]);
    expect(gatesOf(`key = ${FAKE.awsKeyId} # gitleaks:allow`, "aws-access-token")).toEqual(["pragma"]);
    expect(gatesOf(`key = ${FAKE.awsKeyId} # gitleaks:allow`, "aws-access-token", { pragmas: false })).toEqual([]);
    expect(gatesOf(`ssh_public_key = "${FAKE.genericSecret}"`, "generic-api-key")).toContain("name-context");
    expect(gatesOf(`token: ghp_${repeated}${FAKE.githubPat.slice(12)}`, "github-pat")).toEqual(["repeated-character"]);
    expect(gatesOf(`token = "SECRETGATE_0123456789abcdef"`, "generic-api-key")).toContain("redacted");
  });

  it("tells an allowlist's stopwords from its regexes, and the global lists apart", () => {
    const stopword = gatesOf(`api_key = "${FAKE.genericSecret.slice(0, 12)}example${FAKE.genericSecret.slice(12)}"`, "generic-api-key");
    expect(stopword).toContain("rule-stopword");
    expect(stopword).not.toContain("rule-allowlist");
    // Letters only: the generic rule's first allowlist regex.
    const letters = gatesOf(`api_key = "qzxjkvwqzjxkvwzqxjkv"`, "generic-api-key");
    expect(letters).toContain("rule-allowlist");
    expect(letters).not.toContain("rule-stopword");
    expect(gatesOf(`secret = "$\{DATABASE_SECRET_VALUE}"`, "password-assignment")).toEqual(expect.arrayContaining(["placeholder", "global-regex"]));
    expect(gatesOf(`api_key = "${FAKE.genericSecret.slice(0, 4)}abcdefghijklmnopqrstuvwxyz0123456789"`, "generic-api-key")).toContain("global-stopword");
  });

  it("runs an extra rule through the same loop: prefilter, value group, gates", () => {
    const extra = { id: "extra-rule", re: /widget_id\s*=\s*"([^"]+)"/, keywords: ["widget_id"], nameTrusting: true };
    expect(traceMatches(`nothing = "here"`, {}, [extra])).toEqual([]);
    const text = `first\nwidget_id = "changeme"\nwidget_id = "Zx9kLm2Qw8rT5yU" # gitleaks:allow\npublic_key_widget_id = "Zx9kLm2Qw8rT5yU"\nwidget_id = "Zx9kLm2Qw8rT5yU"`;
    const found = traceMatches(text, {}, [extra]).filter((m) => m.ruleId === "extra-rule");
    expect(found.map((m) => [m.secret, m.line, m.gates])).toEqual([
      ["changeme", 1, ["placeholder"]],
      ["Zx9kLm2Qw8rT5yU", 2, ["pragma"]],
      ["Zx9kLm2Qw8rT5yU", 3, ["name-context"]],
      ["Zx9kLm2Qw8rT5yU", 4, []],
    ]);
    expect(text.slice(found[0]!.start, found[0]!.end)).toBe("changeme");
    // The engine's own rules are untouched by the extra one.
    expect(traceMatches(text, {}, [extra]).filter((m) => m.ruleId !== "extra-rule")).toEqual(traceMatches(text));
  });

  it("gives nothing for a file under the global path allowlist", () => {
    const text = `GITHUB_TOKEN=${FAKE.githubPat}`;
    expect(isGloballyAllowedPath("node_modules/pkg/index.js")).toBe(true);
    expect(isGloballyAllowedPath("assets/logo.svg")).toBe(true);
    expect(isGloballyAllowedPath("src/index.js")).toBe(false);
    expect(traceMatches(text, { sourcePath: "node_modules/pkg/index.js" })).toEqual([]);
    expect(strip(text, { sourcePath: "src/index.js" })).toEqual(scan(text));
    expect(scan(text)).toHaveLength(1);
    expect(traceMatches("")).toEqual([]);
  });
});
