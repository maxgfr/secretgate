import { describe, expect, it } from "vitest";
import { luhnValid } from "../../src/engine/luhn.js";

describe("luhnValid", () => {
  it("accepts classic valid numbers", () => {
    expect(luhnValid("4111111111111111")).toBe(true);
    expect(luhnValid("79927398713")).toBe(true);
  });

  it("rejects a near-miss (last digit off by one)", () => {
    expect(luhnValid("4111111111111112")).toBe(false);
    expect(luhnValid("79927398714")).toBe(false);
  });

  it("rejects non-digit input", () => {
    expect(luhnValid("4111-1111-1111-1111x")).toBe(false);
    expect(luhnValid("")).toBe(false);
  });

  it("ignores separators when told to", () => {
    expect(luhnValid("4111 1111 1111 1111", { stripSeparators: true })).toBe(true);
    expect(luhnValid("4111-1111-1111-1111", { stripSeparators: true })).toBe(true);
  });
});
