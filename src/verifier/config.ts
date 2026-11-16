// The `verifier` entry of ~/.secretgate/config.json, read on every hook: kept
// apart from the verifier itself so that reading it loads nothing else.

export type ThresholdPreset = "f1" | "f05" | "f2";
export const THRESHOLD_PRESETS: readonly ThresholdPreset[] = ["f1", "f05", "f2"];

export interface VerifierConfig {
  enabled: boolean;
  threshold: ThresholdPreset;
  /** Why the `verifier` entry of config.json was not understood (then it is off). */
  invalid?: string;
}

export const VERIFIER_OFF: VerifierConfig = { enabled: false, threshold: "f1" };

/** The `verifier` entry of ~/.secretgate/config.json: `{ "enabled": true, "threshold": "f1" }`. */
export function readVerifierConfig(raw: unknown): VerifierConfig {
  if (raw === undefined) return VERIFIER_OFF;
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return { ...VERIFIER_OFF, invalid: "verifier must be an object" };
  const v = raw as Record<string, unknown>;
  const unknown = Object.keys(v).find((k) => k !== "enabled" && k !== "threshold");
  if (unknown !== undefined) return { ...VERIFIER_OFF, invalid: `verifier.${unknown} is not a known key (enabled, threshold)` };
  if (v.enabled !== undefined && typeof v.enabled !== "boolean") return { ...VERIFIER_OFF, invalid: "verifier.enabled must be true or false" };
  if (v.threshold !== undefined && !THRESHOLD_PRESETS.includes(v.threshold as ThresholdPreset))
    return { ...VERIFIER_OFF, invalid: 'verifier.threshold must be "f1", "f05" or "f2"' };
  return { enabled: v.enabled === true, threshold: (v.threshold as ThresholdPreset | undefined) ?? "f1" };
}
