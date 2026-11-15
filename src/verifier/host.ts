// A host for the secrets verifier of sky-web (s6-secrets-verify-pico), vendored
// from skycmd's crates/sky-web/js/verify-host.mjs as published with the model
// (Hugging Face maxgfr/s6-secrets-verify-pico at commit
// 9d44c27848bc13ea6015aab13b019710070737a5, engine/verify-host.mjs, sha256
// 7190b42fe2acc444362cf84e92a962221cfd97bad6acb274556b6854ee0ac0ce), ported
// to this project's TypeScript style. It is reviewed source: secretgate never
// downloads or runs the published JavaScript, only the four data files
// (two WebAssembly builds, the model, the word list), each pinned by sha256.
//
// It instantiates sky_web_bg.wasm (SIMD128) or sky_web_relaxed_bg.wasm
// (relaxed SIMD) itself, without the wasm-bindgen glue, and calls the
// `SecretVerifier` exports. The module's only reach out of its sandbox is the
// five imports below: an Error constructor, a string reader, a throw, a clock
// and a table initialiser. wasm-bindgen names them by a stem and a hash of the
// build; `checkImports` refuses a module that asks for anything else.
//
// The candidate JSON is documented in skycmd's crates/sky-web/src/verify.rs: a
// raw record of the generator `sg-cand-1` is accepted as it is.
//
// Changes from the published file: types; the WebAssembly API is read off
// globalThis (see `webAssembly`); `judgeMany` is left out (secretgate judges
// one candidate at a time, to stop at its budget between two).

const IMPORT_MODULE = "./sky_web_bg.js";

// The part of the WebAssembly JS API this host uses. The project's TypeScript
// library is ES2022 without the DOM, which declares none of it; reading it off
// globalThis also covers a runtime that has no WebAssembly at all.
export interface WasmModule {
  readonly __wasmModule?: never;
}
interface WasmTable {
  grow(delta: number): number;
  set(index: number, value: unknown): void;
  get(index: number): unknown;
}
interface WebAssemblyApi {
  Module: { new (bytes: Uint8Array): WasmModule; imports(module: WasmModule): Array<{ module: string; name: string; kind: string }> };
  Instance: new (module: WasmModule, imports: Record<string, Record<string, unknown>>) => { exports: Record<string, unknown> };
  validate(bytes: Uint8Array): boolean;
}

/** The runtime's WebAssembly API; throws when there is none. */
export function webAssembly(): WebAssemblyApi {
  const api = (globalThis as { WebAssembly?: WebAssemblyApi }).WebAssembly;
  if (api === undefined) throw new Error("this runtime has no WebAssembly");
  return api;
}

type Role = "error" | "stringGet" | "throw" | "now" | "initTable";

// stem -> what the import does; a name is the stem followed by a hexadecimal hash
const STEMS: Array<[string, Role]> = [
  ["__wbg_Error_", "error"],
  ["__wbg___wbindgen_string_get_", "stringGet"],
  ["__wbg___wbindgen_throw_", "throw"],
  ["__wbg_now_", "now"],
];

function roleOf(name: string): Role | null {
  if (name === "__wbindgen_init_externref_table") return "initTable";
  for (const [stem, role] of STEMS) {
    if (name.startsWith(stem) && /^[0-9a-f]{8,}$/.test(name.slice(stem.length))) return role;
  }
  return null;
}

/** The import name of each role; throws unless the module asks for exactly the five imports. */
export function checkImports(module: WasmModule): Record<Role, string> {
  const names: Partial<Record<Role, string>> = {};
  for (const i of webAssembly().Module.imports(module)) {
    const role = i.module === IMPORT_MODULE && i.kind === "function" ? roleOf(i.name) : null;
    if (role === null || names[role]) throw new Error(`the WebAssembly module asks for an unexpected import: ${i.module} ${i.name}`);
    names[role] = i.name;
  }
  if (Object.keys(names).length !== 5) throw new Error("the WebAssembly module is not a sky-web build");
  return names as Record<Role, string>;
}

/** What the model answers for one candidate. */
export interface Judgement {
  p_real: number;
  state_tokens: number;
  truncated: boolean;
  micros: number;
}

export interface Thresholds {
  tau_f1: number | null;
  tau_f05: number | null;
  tau_f2: number | null;
}

export interface WasmVerifier {
  /** One candidate (object or JSON text) -> {p_real, state_tokens, truncated, micros}. */
  judge(candidate: unknown): Judgement;
  /** The state text the model reads for a candidate. */
  state(candidate: unknown): string;
  /** {tau_f1, tau_f05, tau_f2}: the operating thresholds stored in the model file. */
  thresholds(): Thresholds;
  /** {name, n_params, file_bytes, window, words}. */
  info(): Record<string, unknown>;
  /** Releases the model and the word list (the instance's memory stays allocated). */
  free(): void;
}

/** A verifier from a compiled sky-web module, the model's GGUF bytes and the word list's bytes. */
export function verifierFromModule(module: WasmModule, modelBytes: Uint8Array, wordsBytes: Uint8Array): WasmVerifier {
  const names = checkImports(module);
  // The exports are untyped: wasm-bindgen's calling convention, as the glue uses it.
  let wasm: any;
  const decoder = new TextDecoder("utf-8", { ignoreBOM: true, fatal: true });
  const encoder = new TextEncoder();
  // the memory may grow on any allocation: never keep a view of it
  const bytes = (): Uint8Array => new Uint8Array(wasm.memory.buffer);
  const readString = (ptr: number, len: number): string => decoder.decode(bytes().subarray(ptr >>> 0, (ptr >>> 0) + len));
  // the callee takes ownership of what is passed and frees it
  const pass = (data: Uint8Array): [number, number] => {
    const ptr = wasm.__wbindgen_malloc(data.length, 1) >>> 0;
    bytes().set(data, ptr);
    return [ptr, data.length];
  };
  const passString = (s: string): [number, number] => pass(encoder.encode(s));
  const takeRef = (idx: number): unknown => {
    const value = wasm.__wbindgen_externrefs.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
  };
  const asError = (v: unknown): Error => (v instanceof Error ? v : new Error(String(v)));
  // a returned string is copied out, then freed
  const takeString = (ptr: number, len: number): string => {
    try {
      return readString(ptr, len);
    } finally {
      wasm.__wbindgen_free(ptr, len, 1);
    }
  };
  const imports: Record<string, Record<string, unknown>> = {
    [IMPORT_MODULE]: {
      [names.error]: (ptr: number, len: number) => new Error(readString(ptr, len)),
      [names.stringGet]: (retptr: number, obj: unknown) => {
        const [ptr, len] = typeof obj === "string" ? passString(obj) : [0, 0];
        const view = new DataView(wasm.memory.buffer);
        view.setInt32(retptr + 4, len, true);
        view.setInt32(retptr, ptr, true);
      },
      [names.throw]: (ptr: number, len: number) => {
        throw new Error(readString(ptr, len));
      },
      [names.now]: () => performance.now(),
      [names.initTable]: () => {
        const table = wasm.__wbindgen_externrefs as WasmTable;
        const offset = table.grow(4);
        table.set(0, undefined);
        table.set(offset, undefined);
        table.set(offset + 1, null);
        table.set(offset + 2, true);
        table.set(offset + 3, false);
      },
    },
  };
  wasm = new (webAssembly().Instance)(module, imports).exports;
  wasm.__wbindgen_start();

  const created = wasm.secretverifier_new(...pass(modelBytes), ...pass(wordsBytes));
  if (created[2]) throw asError(takeRef(created[1]));
  let self: number = created[0];
  const live = (): number => {
    if (!self) throw new Error("the verifier was freed");
    return self;
  };
  const asJson = (x: unknown): string => (typeof x === "string" ? x : JSON.stringify(x));
  // a method returning Result<String, JsError>: [ptr, len, error ref, is error]
  const call = (fn: (...args: number[]) => number[], arg: unknown): string => {
    const ret = fn(live(), ...passString(asJson(arg)));
    if (ret[3]) throw asError(takeRef(ret[2]!));
    return takeString(ret[0]!, ret[1]!);
  };
  return {
    judge: (candidate) => JSON.parse(call(wasm.secretverifier_judge, candidate)) as Judgement,
    state: (candidate) => call(wasm.secretverifier_state, candidate),
    thresholds: () => JSON.parse(takeString(...(wasm.secretverifier_thresholds(live()) as [number, number]))) as Thresholds,
    info: () => JSON.parse(takeString(...(wasm.secretverifier_info(live()) as [number, number]))) as Record<string, unknown>,
    free: () => {
      if (self) wasm.__wbg_secretverifier_free(self, 0);
      self = 0;
    },
  };
}

/** Synchronous compile and load (Node, Bun). */
export function loadVerifier(wasmBytes: Uint8Array, modelBytes: Uint8Array, wordsBytes: Uint8Array): WasmVerifier {
  return verifierFromModule(new (webAssembly().Module)(wasmBytes), modelBytes, wordsBytes);
}
