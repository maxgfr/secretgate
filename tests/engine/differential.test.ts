import { describe, expect, it } from "vitest";
import { gitleaksPath, scanWithGitleaks } from "../../src/engine/gitleaks-bin.js";
import { scan } from "../../src/engine/scanner.js";
import { FAKE } from "../fixtures/fake-tokens.js";

// Machine check on Go->JS regex-conversion fidelity: run the REAL gitleaks
// binary and the JS engine over the same payloads and require the JS engine
// to find everything gitleaks finds (superset is fine — we add built-ins like
// credit cards that gitleaks doesn't ship).
// Runs only when opted in (CI job installs gitleaks): SECRETGATE_DIFFERENTIAL=1.
const enabled = process.env.SECRETGATE_DIFFERENTIAL === "1" && gitleaksPath() !== null;

describe.skipIf(!enabled)("differential: JS engine vs real gitleaks", () => {
  const payloads = [
    `config:\n  key: ${FAKE.awsKeyId}\n`,
    `GITHUB_TOKEN=${FAKE.githubPat}`,
    `anthropic: ${FAKE.anthropicKey}`,
    `slack: ${FAKE.slackBotToken}`,
    `token = "${FAKE.genericSecret}"`,
    FAKE.privateKey,
    ["multi:", `a=${FAKE.awsKeyId}`, `b=${FAKE.githubPat}`].join("\n"),
  ];

  for (const [i, payload] of payloads.entries()) {
    it(`payload ${i}: JS findings are a superset of gitleaks findings`, async () => {
      const glRules = new Set((await scanWithGitleaks(payload)).map((f) => f.ruleId));
      const jsRules = new Set(scan(payload).map((f) => f.ruleId));
      for (const rule of glRules) {
        expect(jsRules, `gitleaks found '${rule}' but the JS engine did not`).toContain(rule);
      }
      expect(glRules.size, "gitleaks found nothing on a payload that should leak — check the harness").toBeGreaterThan(0);
    });
  }
});
