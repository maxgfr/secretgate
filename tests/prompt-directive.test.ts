import { describe, expect, it } from "vitest";
import { promptDirective } from "../src/prompt-directive.js";

describe("promptDirective — explicit instructions only", () => {
  it.each([
    "désactive secretgate",
    "Désactive secretgate pour cette session",
    "desactive secretgate stp",
    "disable secretgate",
    "Please disable secretgate for this session.",
    "turn off secretgate",
    "secretgate off",
    "coupe secretgate",
    "désactive `secretgate`",
  ])("disables on %j", (prompt) => {
    expect(promptDirective(prompt)).toEqual({ action: "disable", liftScope: false });
  });

  it("finds the directive on its own line of a longer prompt", () => {
    expect(promptDirective("désactive secretgate\nensuite lis le fichier de config")).toEqual({ action: "disable", liftScope: false });
  });

  it.each([
    "/secretgate disable",
    "/secretgate désactive",
    "/secretgate off",
    "$secretgate disable",
    "/secretgate desactiver",
  ])("the skill invoked by name disables: %j", (prompt) => {
    expect(promptDirective(prompt)).toEqual({ action: "disable", liftScope: false });
  });

  it("the skill form handles scope and enable too, and ignores its other commands", () => {
    expect(promptDirective("/secretgate disable scope")).toEqual({ action: "disable", liftScope: true });
    expect(promptDirective("/secretgate désactive --scope")).toEqual({ action: "disable", liftScope: true });
    expect(promptDirective("/secretgate enable")).toEqual({ action: "enable" });
    expect(promptDirective("$secretgate réactive")).toEqual({ action: "enable" });
    expect(promptDirective('"/secretgate disable"')).toEqual({ action: "disable", liftScope: false });
    expect(promptDirective("/secretgate status")).toBeUndefined();
    expect(promptDirective("/secretgate install")).toBeUndefined();
  });

  it("lifts the scope only when asked", () => {
    expect(promptDirective("désactive secretgate et le scope")).toEqual({ action: "disable", liftScope: true });
    expect(promptDirective("disable secretgate and the scope")).toEqual({ action: "disable", liftScope: true });
  });

  it.each([
    "réactive secretgate",
    "reactive secretgate",
    "enable secretgate",
    "turn secretgate back on",
    "secretgate on",
    "re-enable secretgate",
  ])("re-enables on %j", (prompt) => {
    expect(promptDirective(prompt)).toEqual({ action: "enable" });
  });

  it.each([
    "comment je fais pour désactiver secretgate ?",
    "le test doit vérifier que disable secretgate marche bien",
    "fix the bug where disable secretgate pauses the wrong session",
    "désactive le linter",
    "secretgate is great",
    "",
  ])("ignores discussion, not instruction: %j", (prompt) => {
    expect(promptDirective(prompt)).toBeUndefined();
  });
});
