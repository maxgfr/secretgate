// Deep-walk every string value of an unknown JSON-ish structure and map it.
// Tool inputs/outputs vary per tool and per agent version — walking strings
// wherever they are is robust to schema drift, unlike hard-coded field names.
//
// Iterative (explicit stack), not recursive: a deeply nested tool response
// would otherwise overflow the call stack (~1500 levels) and throw. In the hook
// path a throw fails closed (safe), but that would withhold a legitimately deep
// output — walking iteratively redacts it instead. Object KEYS are scanned too
// (a secret can hide in a key name) while preserving the mapping.
export function mapStrings(value: unknown, fn: (s: string) => string): { value: unknown; changed: boolean } {
  let changed = false;
  const map = (s: string): string => {
    const out = fn(s);
    if (out !== s) changed = true;
    return out;
  };

  if (typeof value === "string") return { value: map(value), changed };
  if (value === null || typeof value !== "object") return { value, changed };

  const root: any = Array.isArray(value) ? [] : {};
  // stack frames: process `src` into the already-created `dest` container
  const stack: Array<{ src: any; dest: any }> = [{ src: value, dest: root }];
  while (stack.length > 0) {
    const { src, dest } = stack.pop()!;
    if (Array.isArray(src)) {
      for (let i = 0; i < src.length; i++) {
        const v = src[i];
        if (typeof v === "string") dest[i] = map(v);
        else if (v !== null && typeof v === "object") {
          dest[i] = Array.isArray(v) ? [] : {};
          stack.push({ src: v, dest: dest[i] });
        } else dest[i] = v;
      }
    } else {
      for (const key of Object.keys(src)) {
        const mappedKey = map(key);
        const v = src[key];
        if (typeof v === "string") dest[mappedKey] = map(v);
        else if (v !== null && typeof v === "object") {
          dest[mappedKey] = Array.isArray(v) ? [] : {};
          stack.push({ src: v, dest: dest[mappedKey] });
        } else dest[mappedKey] = v;
      }
    }
  }
  return { value: root, changed };
}
