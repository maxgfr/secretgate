// Deep-walk every string value of an unknown JSON-ish structure and map it.
// Tool inputs/outputs vary per tool and per agent version — walking strings
// wherever they are is robust to schema drift, unlike hard-coded field names.
export function mapStrings(value: unknown, fn: (s: string) => string): { value: unknown; changed: boolean } {
  let changed = false;
  const visit = (v: unknown): unknown => {
    if (typeof v === "string") {
      const mapped = fn(v);
      if (mapped !== v) changed = true;
      return mapped;
    }
    if (Array.isArray(v)) return v.map(visit);
    if (v !== null && typeof v === "object") {
      const out: Record<string, unknown> = {};
      for (const [k, inner] of Object.entries(v as Record<string, unknown>)) out[k] = visit(inner);
      return out;
    }
    return v;
  };
  return { value: visit(value), changed };
}
