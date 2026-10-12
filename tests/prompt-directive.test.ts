import { describe, expect, it } from "vitest";
import { promptDirective } from "../src/prompt-directive.js";

describe("promptDirective — the skill invoked by name, on the first line", () => {
  it.each([
    "/secretgate disable",
    "/secretgate off",
    "/secretgate pause",
    "/secretgate stop",
    "$secretgate disable",
    "/SecretGate Off",
    "/secretgate off.",
    '"/secretgate disable"',
    "  /secretgate off  ",
  ])("disables on %j", (prompt) => {
    expect(promptDirective(prompt)).toEqual({ action: "disable", liftScope: false });
  });

  it("lifts the scope only when asked", () => {
    expect(promptDirective("/secretgate off scope")).toEqual({ action: "disable", liftScope: true });
    expect(promptDirective("/secretgate disable --scope")).toEqual({ action: "disable", liftScope: true });
    expect(promptDirective("$secretgate pause scope")).toEqual({ action: "disable", liftScope: true });
  });

  it.each(["/secretgate enable", "/secretgate on", "/secretgate resume", "$secretgate on"])("re-enables on %j", (prompt) => {
    expect(promptDirective(prompt)).toEqual({ action: "enable" });
  });

  it("acts when the directive is the first non-empty line, whatever follows", () => {
    expect(promptDirective("/secretgate off\nthen run the tests")).toEqual({ action: "disable", liftScope: false });
    expect(promptDirective("\n\n  /secretgate on\r\nthanks")).toEqual({ action: "enable" });
  });

  it.each([
    "why does this fail?\n/secretgate off",
    "here is the log:\n```\n/secretgate off\n```",
    "> /secretgate off",
    "please /secretgate off",
    "/secretgate off now please",
  ])("a directive anywhere but alone on the first line does nothing: %j", (prompt) => {
    expect(promptDirective(prompt)).toBeUndefined();
  });

  it.each([
    "désactive secretgate",
    "désactive secretgate et le scope",
    "disable secretgate",
    "turn off secretgate",
    "secretgate off",
    "secretgate: off",
    "réactive secretgate",
    "enable secretgate",
    "/secretgate désactive",
    "$secretgate réactive",
  ])("natural language no longer switches anything: %j", (prompt) => {
    expect(promptDirective(prompt)).toBeUndefined();
  });

  it.each(["/secretgate status", "/secretgate install", "/secretgate", "secretgate is great", ""])("ignores other commands and prose: %j", (prompt) => {
    expect(promptDirective(prompt)).toBeUndefined();
  });
});
