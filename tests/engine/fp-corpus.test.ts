import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { scan } from "../../src/engine/scanner.js";

const CORPUS_DIR = join(__dirname, "..", "fixtures", "fp-corpus");

// The false-positive budget is pinned at ZERO: everyday content (lockfiles,
// git logs, uuids, config code, base64 blobs) must never trip the firewall,
// or users will disable it. Scanned WITHOUT sourcePath on purpose — that is
// the worst case (content pasted into a prompt gets no path-based allowlist).
describe("false-positive corpus", () => {
  for (const file of readdirSync(CORPUS_DIR)) {
    it(`${file} produces zero findings`, () => {
      const text = readFileSync(join(CORPUS_DIR, file), "utf8");
      const findings = scan(text);
      expect(findings.map((f) => `${f.ruleId}: ${f.secret.slice(0, 20)}…`)).toEqual([]);
    });
  }

  it("a 50KB mixed payload scans fast (median of 5 under 500ms)", () => {
    const parts = readdirSync(CORPUS_DIR).map((f) => readFileSync(join(CORPUS_DIR, f), "utf8"));
    let payload = "";
    while (payload.length < 50_000) payload += parts.join("\n");
    const times: number[] = [];
    for (let i = 0; i < 5; i++) {
      const t0 = performance.now();
      scan(payload);
      times.push(performance.now() - t0);
    }
    times.sort((a, b) => a - b);
    const median = times[2]!;
    // CI threshold is generous for shared runners; local target is <50ms.
    expect(median).toBeLessThan(500);
  });
});
