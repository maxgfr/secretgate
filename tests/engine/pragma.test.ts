import { describe, expect, it } from "vitest";
import { pragmaAllowedLines } from "../../src/engine/pragma.js";

describe("pragmaAllowedLines", () => {
  it("marks lines carrying an inline allow pragma", () => {
    const text = ['const a = "x";', 'const b = "y"; // pragma: allowlist secret', 'const c = "z";'].join("\n");
    const allowed = pragmaAllowedLines(text);
    expect(allowed.has(0)).toBe(false);
    expect(allowed.has(1)).toBe(true);
    expect(allowed.has(2)).toBe(false);
  });

  it("supports the gitleaks:allow marker too", () => {
    const allowed = pragmaAllowedLines('token = "abc" # gitleaks:allow');
    expect(allowed.has(0)).toBe(true);
  });

  it("supports allowlist nextline secret", () => {
    const text = ["# pragma: allowlist nextline secret", 'token = "abc"'].join("\n");
    const allowed = pragmaAllowedLines(text);
    expect(allowed.has(1)).toBe(true);
    expect(allowed.has(0)).toBe(false);
  });
});
