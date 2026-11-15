import { mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { applyEdits, modify, type ParseError, parse as parseJsonc, printParseErrorCode } from "jsonc-parser";
import type { Io } from "../cli.js";
import { loadConfig } from "../config.js";
import { rewriteFileAtomic } from "../fs-atomic.js";
import { defaultVaultHome } from "../vault/vault.js";
import { ASSET_BASE_URL, ASSETS, assetDir, assetStates, fetchAssets, MODEL_COMMIT, MODEL_NAME } from "./assets.js";
import { THRESHOLD_PRESETS, type ThresholdPreset, type VerifierConfig } from "./config.js";
import { loadEngine, VERIFIER_BUDGET_MS, VERIFIER_MAX_CANDIDATES, VERIFIER_RULE_ID } from "./verifier.js";

// `secretgate verifier [status | fetch | on [--threshold f1|f05|f2] | off]`.

const RESULT_URL =
  "https://github.com/maxgfr/skycmd/blob/main/BENCH.md#s6-secrets-verify-pico-s6-secrets-v2-a-verifier-of-rule-candidates-pre-registered-gate-failed";

const USAGE = `usage: secretgate verifier [status]           what is on, whether the assets are there and verified, which engine loads
       secretgate verifier fetch            download the four pinned data files (the only command that downloads)
       secretgate verifier on [--threshold f1|f05|f2]
       secretgate verifier off
`;

export const VERIFIER_NOTICE = `EXPERIMENTAL. The verifier is the model ${MODEL_NAME}, which FAILED its pre-registered gate: on 221 real
test repositories (CredData) its line F1 is 0.856 against 0.733 for the best rule scanner, +0.123 where the gate
asked for +0.15; the system "rules or verifier" failed the same gate. It is published as a result, not as a
validated detector. Read docs/verifier.md and ${RESULT_URL}
`;

/** One line for `secretgate status`. */
export function statusLine(cfg: VerifierConfig): string {
  if (cfg.invalid) return `verifier  !! the "verifier" entry of config.json is invalid (${cfg.invalid}) — the verifier is OFF\n`;
  if (!cfg.enabled) return "verifier  off (experimental, opt-in: `secretgate verifier` for details)\n";
  const states = assetStates();
  const bad = states.filter((s) => s.state !== "verified");
  if (bad.length > 0)
    return `verifier  ON (threshold ${cfg.threshold}) but SKIPPED: ${bad.map((s) => `${s.pin.file} ${s.state}`).join(", ")} — run \`secretgate verifier fetch\`; the rules run as without it\n`;
  const load = tryLoad(cfg.threshold);
  if ("error" in load)
    return `verifier  ON (threshold ${cfg.threshold}) but SKIPPED: the engine does not load here (${load.error}); the rules run as without it\n`;
  return `verifier  ON (experimental), threshold ${cfg.threshold} (tau ${load.tau.toFixed(4)}), assets verified, engine ${load.build} build — redacts what it accepts as ${VERIFIER_RULE_ID}\n`;
}

function tryLoad(preset: ThresholdPreset): { build: string; tau: number; ms: number } | { error: string } {
  try {
    const t0 = performance.now();
    const e = loadEngine(preset);
    return { build: e.build, tau: e.tau, ms: performance.now() - t0 };
  } catch (err) {
    return { error: err instanceof Error ? err.message.split("\n")[0]! : String(err) };
  }
}

function configPath(): string {
  return join(defaultVaultHome(), "config.json");
}

/** Sets the `verifier` entry of ~/.secretgate/config.json, keeping the rest of the file (comments too). */
export function writeVerifierConfig(value: { enabled: boolean; threshold: ThresholdPreset }): void {
  const path = configPath();
  mkdirSync(defaultVaultHome(), { recursive: true, mode: 0o700 });
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    text = "";
  }
  if (text.trim() === "") text = "{}\n";
  const errors: ParseError[] = [];
  const current = parseJsonc(text, errors, { allowTrailingComma: true, disallowComments: false }) as unknown;
  if (errors.length > 0) {
    const line = text.slice(0, errors[0]!.offset).split("\n").length;
    throw new Error(`${path} is not valid JSON (${printParseErrorCode(errors[0]!.error)} at line ${line}) — fix it by hand, nothing was written`);
  }
  if (current === null || typeof current !== "object" || Array.isArray(current)) throw new Error(`${path} must be a JSON object — nothing was written`);
  text = applyEdits(text, modify(text, ["verifier"], value, { formattingOptions: { insertSpaces: true, tabSize: 2, eol: "\n" } }));
  rewriteFileAtomic(path, text, 0o600);
}

export async function cmdVerifier(args: string[], io: Io): Promise<number> {
  const [sub = "status", ...rest] = args;
  if (sub === "status" && rest.length === 0) return status(io);
  if (sub === "fetch" && rest.length === 0) {
    io.stdout(`secretgate: downloading the ${MODEL_NAME} data files, pinned at commit ${MODEL_COMMIT}, from ${ASSET_BASE_URL}\n`);
    io.stdout(`secretgate: into ${assetDir()}\n`);
    try {
      await fetchAssets((line) => io.stdout(`  ${line}\n`));
    } catch (err) {
      io.stderr(`verifier fetch: ${err instanceof Error ? err.message : String(err)}\n`);
      return 1;
    }
    io.stdout("secretgate: every file matches its pinned sha256.\n");
    if (!loadConfig().verifier.enabled) io.stdout("secretgate: the verifier is still off — `secretgate verifier on` switches it on.\n");
    return 0;
  }
  if (sub === "on") {
    let threshold: ThresholdPreset = "f1";
    for (let i = 0; i < rest.length; i++) {
      const v = rest[i + 1] as ThresholdPreset | undefined;
      if (rest[i] === "--threshold" && v !== undefined && THRESHOLD_PRESETS.includes(v)) {
        threshold = v;
        i++;
      } else {
        io.stderr(`verifier on: expected --threshold f1, f05 or f2\n${USAGE}`);
        return 2;
      }
    }
    try {
      writeVerifierConfig({ enabled: true, threshold });
    } catch (err) {
      io.stderr(`verifier on: ${err instanceof Error ? err.message : String(err)}\n`);
      return 2;
    }
    io.stdout(`secretgate: the verifier is ON (threshold ${threshold}), in ${configPath()}.\n${VERIFIER_NOTICE}`);
    const missing = assetStates().filter((s) => s.state !== "verified");
    if (missing.length > 0) io.stdout("secretgate: its data files are not there yet: until `secretgate verifier fetch`, it is skipped.\n");
    return 0;
  }
  if (sub === "off" && rest.length === 0) {
    try {
      writeVerifierConfig({ enabled: false, threshold: loadConfig().verifier.threshold });
    } catch (err) {
      io.stderr(`verifier off: ${err instanceof Error ? err.message : String(err)}\n`);
      return 2;
    }
    io.stdout("secretgate: the verifier is off. The rules are unchanged.\n");
    return 0;
  }
  io.stderr(USAGE);
  return 2;
}

function status(io: Io): number {
  const cfg = loadConfig().verifier;
  io.stdout(VERIFIER_NOTICE);
  io.stdout("\n");
  io.stdout(
    cfg.invalid
      ? `config    !! the "verifier" entry of ${configPath()} is invalid (${cfg.invalid}): the verifier is OFF\n`
      : `config    ${cfg.enabled ? `ON, threshold ${cfg.threshold}` : "off"} (${configPath()})\n`,
  );
  io.stdout(`assets    ${assetDir()}\n`);
  const states = assetStates();
  for (const s of states)
    io.stdout(`  ${s.state === "verified" ? "verified" : s.state.toUpperCase().padEnd(8)}  ${s.pin.file} (${s.pin.bytes} bytes, sha256 ${s.pin.sha256})\n`);
  if (states.some((s) => s.state !== "verified")) {
    io.stdout("engine    not loaded: `secretgate verifier fetch` downloads the files\n");
  } else {
    const load = tryLoad(cfg.threshold);
    io.stdout(
      "error" in load
        ? `engine    !! does not load here: ${load.error}\n`
        : `engine    the ${load.build} build loads (${load.ms.toFixed(0)} ms); tau_${cfg.threshold} ${load.tau}\n`,
    );
  }
  io.stdout(
    `budget    ${VERIFIER_BUDGET_MS} ms and ${VERIFIER_MAX_CANDIDATES} candidates per hook event, the load included; past it the rest is not judged (SECRETGATE_DEBUG=verifier says so)\n`,
  );
  io.stdout(`files     ${ASSETS.length} data files, pinned by sha256; the JavaScript that loads them is part of secretgate\n`);
  return 0;
}
