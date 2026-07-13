import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { scanWithGitleaks } from "../../src/engine/gitleaks-bin.js";

// Stub "gitleaks" executables so the hybrid path is tested without the real
// binary: each writes a canned report to the --report-path argument.
function stubGitleaks(script: string): string {
  const dir = mkdtempSync(join(tmpdir(), "secretgate-stub-"));
  const bin = join(dir, "gitleaks");
  writeFileSync(bin, `#!/bin/sh\n${script}\n`);
  chmodSync(bin, 0o755);
  return bin;
}

// The report path is always the argument right after --report-path (arg 8).
const REPORT_ARG = "$8";

describe("scanWithGitleaks", () => {
  it("returns [] when the binary reports no leaks (exit 0)", async () => {
    const bin = stubGitleaks(`cat > /dev/null; echo '[]' > "${REPORT_ARG}"; exit 0`);
    await expect(scanWithGitleaks("clean text", { bin })).resolves.toEqual([]);
  });

  it("parses findings when the binary exits with the leak code", async () => {
    const bin = stubGitleaks(`cat > /dev/null; echo '[{"RuleID":"github-pat","Secret":"tok123"}]' > "${REPORT_ARG}"; exit 99`);
    await expect(scanWithGitleaks("whatever", { bin })).resolves.toEqual([{ ruleId: "github-pat", secret: "tok123" }]);
  });

  it("rejects when the binary fails with an unexpected exit code", async () => {
    const bin = stubGitleaks(`cat > /dev/null; echo 'boom' >&2; exit 3`);
    await expect(scanWithGitleaks("whatever", { bin })).rejects.toThrow(/exited 3/);
  });
});
