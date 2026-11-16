import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { writeFileAtomic } from "../fs-atomic.js";
import { defaultVaultHome } from "../vault/vault.js";

// The verifier's data files: two builds of the sky-web engine (WebAssembly),
// the model and the word list of its `word` feature. Published with the model
// on Hugging Face, and pinned here twice: by the repository commit in the URL
// (a commit of a Hugging Face repository never changes) and by the sha256 and
// size of each file, checked when it is downloaded and again every time it is
// loaded. Nothing else is downloaded: the JavaScript host that loads them is
// vendored source (./host.ts). Only `secretgate verifier fetch` downloads; a
// hook never touches the network.

export const MODEL_NAME = "s6-secrets-verify-pico";
export const MODEL_COMMIT = "9d44c27848bc13ea6015aab13b019710070737a5";
export const ASSET_BASE_URL = `https://huggingface.co/maxgfr/${MODEL_NAME}/resolve/${MODEL_COMMIT}/engine/`;

export type AssetName = "sky_web_bg.wasm" | "sky_web_relaxed_bg.wasm" | "s6-secrets-verify-pico.gguf" | "dictionary.txt";

export interface AssetPin {
  file: AssetName;
  bytes: number;
  sha256: string;
  what: string;
}

export const ASSETS: readonly AssetPin[] = [
  {
    file: "sky_web_bg.wasm",
    bytes: 1_222_078,
    sha256: "2ccf6fe227e9a773a19701283f938bded6258be951d879b684da8f23b4f78311",
    what: "the engine, SIMD128 build",
  },
  {
    file: "sky_web_relaxed_bg.wasm",
    bytes: 1_219_957,
    sha256: "d09fc19362993dc90c7e3c1f2bfe18147060599397c6ee2a759c9f7d12b86236",
    what: "the engine, relaxed-SIMD build",
  },
  {
    file: "s6-secrets-verify-pico.gguf",
    bytes: 249_984,
    sha256: "01e6db3fa71cc2c5563dea222c68e040d3994ee2abbb02b25491a51b8cb54f27",
    what: "the model (ternary, full depth, with its three thresholds)",
  },
  {
    file: "dictionary.txt",
    bytes: 1_706_770,
    sha256: "83f3f32b0df5fc92418dac25b8d1317ec537c0d4c6405961c9c06f31159c21e9",
    what: "the word list of the model's `word` feature",
  },
];

const pinOf = (file: AssetName): AssetPin => ASSETS.find((a) => a.file === file)!;

/** Where the files live: secretgate's data directory, one folder per pinned commit. */
export function assetDir(): string {
  return join(defaultVaultHome(), "verifier", `${MODEL_NAME}-${MODEL_COMMIT.slice(0, 12)}`);
}

const sha256 = (bytes: Uint8Array): string => createHash("sha256").update(bytes).digest("hex");

export type AssetState = "verified" | "missing" | "mismatch";

/** Whether `bytes` are the pinned file. */
export function matchesPin(file: AssetName, bytes: Uint8Array): boolean {
  const pin = pinOf(file);
  return bytes.length === pin.bytes && sha256(bytes) === pin.sha256;
}

/** The bytes of a pinned file, or why there are none: missing, or not the pinned file. */
export function readAsset(file: AssetName, dir = assetDir()): { bytes: Uint8Array } | { state: Exclude<AssetState, "verified"> } {
  const path = join(dir, file);
  const st = statSync(path, { throwIfNoEntry: false });
  if (st === undefined || !st.isFile()) return { state: "missing" };
  // A file of the wrong size is refused unread.
  if (st.size !== pinOf(file).bytes) return { state: "mismatch" };
  const bytes = readFileSync(path);
  return matchesPin(file, bytes) ? { bytes } : { state: "mismatch" };
}

/** The state of every pinned file. */
export function assetStates(dir = assetDir()): Array<{ pin: AssetPin; state: AssetState }> {
  return ASSETS.map((pin) => {
    const read = readAsset(pin.file, dir);
    return { pin, state: "bytes" in read ? "verified" : read.state };
  });
}

export type Fetcher = (url: string) => Promise<{ ok: boolean; status: number; url?: string; arrayBuffer(): Promise<ArrayBuffer> }>;

/**
 * Downloads every pinned file that is not already there and verified, checks
 * its size and sha256, and only then writes it (atomically, 0644). A file that
 * does not match its pin is refused and nothing is written for it. Returns one
 * line per file; throws when any file could not be fetched or verified.
 */
export async function fetchAssets(log: (line: string) => void, fetcher: Fetcher = globalThis.fetch as unknown as Fetcher, dir = assetDir()): Promise<void> {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const failures: string[] = [];
  for (const pin of ASSETS) {
    if ("bytes" in readAsset(pin.file, dir)) {
      log(`${pin.file}: already there, sha256 verified`);
      continue;
    }
    const url = ASSET_BASE_URL + pin.file;
    try {
      const res = await fetcher(url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      // Hugging Face redirects to its CDN; the bytes are what is checked.
      if (res.url !== undefined && res.url !== "" && !res.url.startsWith("https://")) throw new Error("redirected off HTTPS");
      const bytes = new Uint8Array(await res.arrayBuffer());
      if (bytes.length !== pin.bytes) throw new Error(`${bytes.length} bytes, expected ${pin.bytes}`);
      const got = sha256(bytes);
      if (got !== pin.sha256) throw new Error(`sha256 ${got}, expected ${pin.sha256}`);
      writeFileAtomic(join(dir, pin.file), bytes, 0o644);
      log(`${pin.file}: downloaded, ${pin.bytes} bytes, sha256 verified`);
    } catch (err) {
      const why = err instanceof Error ? err.message : String(err);
      failures.push(pin.file);
      log(`${pin.file}: REFUSED (${why}) — nothing written`);
    }
  }
  if (failures.length > 0) throw new Error(`could not fetch and verify ${failures.join(", ")}`);
}
