// Dev-only, for scripts/model-compare.mjs: a minimal host for skycmd's
// `sky-web` WebAssembly engine, which runs any of its GGUF decision models.
// What is model-specific (which file, which questions, how text is fed) lives
// in one adapter module per model, e.g. scripts/s6-secrets-pico.mjs, so a
// later model answering another question plugs in beside it without touching
// this host. Not part of the bundle: secretgate does not ship a model (see
// docs/model-comparison.md).
//
// The host is written here instead of running the `sky_web.js` glue that ships
// with the engine, so measuring the model never executes downloaded
// JavaScript: the .wasm and the .gguf run inside the WebAssembly sandbox,
// whose only reach into the process is the five imports below (an Error
// constructor, a string reader, a throw, a clock, a table initialiser). The
// hashed import names are those of the pinned build; `checkImports` refuses
// any other. On the first 200 records of secret_bench it returns the same
// probabilities as the official glue, bit for bit (`--parity`).
import { createHash } from "node:crypto";

// Pinned by commit AND by content: the URL names an immutable commit of the
// model's demo Space on Hugging Face, never `main`, and the build is the one
// that Space serves (the copy on GitHub Pages is rebuilt in place).
export const ENGINE_ASSET = {
  file: "sky_web_bg.wasm",
  url: "https://huggingface.co/spaces/maxgfr/s6-secrets-pico/resolve/0cff076be6b854072ea75d730fb8a25c236d7d6f/pkg/sky_web_bg.wasm",
  sha256: "8a5ffc2cc2a071bfda276cb486a12c8ea575b72a4a59cdda1a4efbfe07dcd99b",
  bytes: 1_158_454,
};

export const sha256Hex = (bytes) => createHash("sha256").update(bytes).digest("hex");

const IMPORT_MODULE = "./sky_web_bg.js";
const IMPORTS = {
  error: "__wbg_Error_30c8987f7c2ed4e2",
  stringGet: "__wbg___wbindgen_string_get_0380ccaa2f57f0d9",
  throw: "__wbg___wbindgen_throw_41e9ee4f547fc59a",
  now: "__wbg_now_c445cae75f697d51",
  initTable: "__wbindgen_init_externref_table",
};

/** Throws unless the module asks for exactly the imports of the pinned build. */
export function checkImports(module) {
  const want = new Set(Object.values(IMPORTS));
  const got = WebAssembly.Module.imports(module);
  const unexpected = got.filter((i) => i.module !== IMPORT_MODULE || i.kind !== "function" || !want.has(i.name));
  if (unexpected.length > 0 || got.length !== want.size) throw new Error("the WebAssembly engine is not the pinned sky-web build");
}

/**
 * Compile the engine, load a model, return a synchronous
 * `decide(qtype, instructions, options[], state) -> { probs }`.
 */
export function loadSkyEngine(wasmBytes, ggufBytes) {
  const module = new WebAssembly.Module(wasmBytes);
  checkImports(module);
  let wasm;
  const decoder = new TextDecoder("utf-8", { ignoreBOM: true, fatal: true });
  const encoder = new TextEncoder();
  // The memory may grow on any allocation: never cache a view of it.
  const bytes = () => new Uint8Array(wasm.memory.buffer);
  const readString = (ptr, len) => decoder.decode(bytes().subarray(ptr >>> 0, (ptr >>> 0) + len));
  const passBytes = (data) => {
    const ptr = wasm.__wbindgen_malloc(data.length, 1) >>> 0;
    bytes().set(data, ptr);
    return [ptr, data.length];
  };
  const takeRef = (idx) => {
    const value = wasm.__wbindgen_externrefs.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
  };
  const asError = (v) => (v instanceof Error ? v : new Error(String(v)));
  const imports = {
    [IMPORT_MODULE]: {
      [IMPORTS.error]: (ptr, len) => new Error(readString(ptr, len)),
      [IMPORTS.stringGet]: (retptr, obj) => {
        const [ptr, len] = typeof obj === "string" ? passBytes(encoder.encode(obj)) : [0, 0];
        const view = new DataView(wasm.memory.buffer);
        view.setInt32(retptr + 4, len, true);
        view.setInt32(retptr, ptr, true);
      },
      [IMPORTS.throw]: (ptr, len) => {
        throw new Error(readString(ptr, len));
      },
      [IMPORTS.now]: () => performance.now(),
      [IMPORTS.initTable]: () => {
        const table = wasm.__wbindgen_externrefs;
        const offset = table.grow(4);
        table.set(0, undefined);
        table.set(offset, undefined);
        table.set(offset + 1, null);
        table.set(offset + 2, true);
        table.set(offset + 3, false);
      },
    },
  };
  wasm = new WebAssembly.Instance(module, imports).exports;
  wasm.__wbindgen_start();
  const [gp, gl] = passBytes(ggufBytes);
  const created = wasm.engine_new(gp, gl);
  if (created[2]) throw asError(takeRef(created[1]));
  const engine = created[0];
  // The published file stores its exit thresholds at 1 (full depth, as it was
  // evaluated); set it explicitly so the depth never depends on the file.
  wasm.engine_setExitThreshold(engine, 1);
  return {
    decide(qtype, instructions, options, state) {
      const args = [qtype, instructions, JSON.stringify(options), state].flatMap((s) => passBytes(encoder.encode(s)));
      const ret = wasm.engine_decide(engine, ...args);
      if (ret[3]) throw asError(takeRef(ret[2]));
      try {
        const answer = JSON.parse(readString(ret[0], ret[1]));
        if (!Array.isArray(answer.probs) || answer.probs.length !== options.length) throw new Error("the engine returned a malformed answer");
        return { probs: answer.probs };
      } finally {
        wasm.__wbindgen_free(ret[0], ret[1], 1);
      }
    },
  };
}
