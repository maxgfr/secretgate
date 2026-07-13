import { describe, expect, it } from "vitest";
import { shannonEntropy } from "../../src/engine/entropy.js";

describe("shannonEntropy", () => {
  it("is 0 for a single repeated character", () => {
    expect(shannonEntropy("aaaa")).toBe(0);
  });

  it("is 1 bit for two equally frequent characters", () => {
    expect(shannonEntropy("aabb")).toBeCloseTo(1.0, 10);
  });

  it("is 2 bits for four equally frequent characters", () => {
    expect(shannonEntropy("abcd")).toBeCloseTo(2.0, 10);
  });

  it("is 4 bits for sixteen distinct characters", () => {
    expect(shannonEntropy("0123456789abcdef")).toBeCloseTo(4.0, 10);
  });

  it("is 0 for the empty string", () => {
    expect(shannonEntropy("")).toBe(0);
  });

  it("scores realistic random tokens above 4.3 and English words below 4.3", () => {
    // built by concatenation so the repo never contains a token-shaped literal
    const random = ["kQ9", "zX2", "mP7", "vB4", "wL8", "nR3", "tY6", "hG5", "jD1", "fC0"].join("");
    expect(shannonEntropy(random)).toBeGreaterThan(4.3);
    expect(shannonEntropy("thequickbrownfoxjumps")).toBeLessThan(4.3);
  });
});
