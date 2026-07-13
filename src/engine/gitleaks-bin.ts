import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";

// Optional hybrid pass: when the real gitleaks binary is installed, run it as
// a second engine over the same payload and merge what it finds. The JS engine
// stays the source of truth (hooks use it exclusively for latency); gitleaks
// adds belt-and-braces coverage in the standalone `scan` CLI.

let cachedPath: string | null | undefined;

export function gitleaksPath(): string | null {
  if (cachedPath !== undefined) return cachedPath;
  const exe = process.platform === "win32" ? "gitleaks.exe" : "gitleaks";
  for (const dir of (process.env.PATH ?? "").split(delimiter)) {
    if (dir && existsSync(join(dir, exe))) {
      cachedPath = join(dir, exe);
      return cachedPath;
    }
  }
  cachedPath = null;
  return null;
}

export interface GitleaksFinding {
  ruleId: string;
  secret: string;
}

// Exit codes: 0 = clean, LEAK_EXIT (via --exit-code) = leaks found, anything
// else = gitleaks itself failed (config error, bad flags…) and we throw.
const LEAK_EXIT = 99;

export function scanWithGitleaks(text: string, opts: { bin?: string; timeoutMs?: number } = {}): Promise<GitleaksFinding[]> {
  const bin = opts.bin ?? gitleaksPath();
  if (!bin) return Promise.resolve([]);
  const dir = mkdtempSync(join(tmpdir(), "secretgate-gl-"));
  const report = join(dir, "report.json");
  return new Promise((resolve, reject) => {
    const child = spawn(bin, ["stdin", "--no-banner", "--exit-code", String(LEAK_EXIT), "--report-format", "json", "--report-path", report], {
      stdio: ["pipe", "ignore", "pipe"],
      timeout: opts.timeoutMs ?? 10_000,
    });
    let stderr = "";
    child.stderr.on("data", (d) => {
      stderr += d;
    });
    child.on("error", (err) => {
      rmSync(dir, { recursive: true, force: true });
      reject(err);
    });
    child.on("close", (code) => {
      try {
        if (code === 0) {
          resolve([]);
          return;
        }
        if (code !== LEAK_EXIT) {
          reject(new Error(`gitleaks exited ${code}: ${stderr.slice(0, 500)}`));
          return;
        }
        const raw = JSON.parse(readFileSync(report, "utf8")) as Array<{ RuleID: string; Secret: string }>;
        resolve(raw.map((f) => ({ ruleId: f.RuleID, secret: f.Secret })));
      } catch (err) {
        reject(err);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });
    child.stdin.end(text);
  });
}
