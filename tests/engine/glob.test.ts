import { describe, expect, it } from "vitest";
import { pathMatchesGlob } from "../../src/engine/allowlist.js";
import { commandTouchesSensitivePath, sensitivePathMatch } from "../../src/paths.js";

describe("pathMatchesGlob — **/ matches whole segments, not filename prefixes", () => {
  it("**/.env matches the file .env at any depth but NOT restored.env", () => {
    expect(pathMatchesGlob(".env", "**/.env")).toBe(true);
    expect(pathMatchesGlob("foo/.env", "**/.env")).toBe(true);
    expect(pathMatchesGlob("a/b/c/.env", "**/.env")).toBe(true);
    expect(pathMatchesGlob("restored.env", "**/.env")).toBe(false);
    expect(pathMatchesGlob("foo/restored.env", "**/.env")).toBe(false);
    expect(pathMatchesGlob("production.env", "**/.env")).toBe(false);
  });

  it("**/.env.* matches .env.local but not restored.env.bak collisions", () => {
    expect(pathMatchesGlob(".env.local", "**/.env.*")).toBe(true);
    expect(pathMatchesGlob("cfg/.env.production", "**/.env.*")).toBe(true);
    expect(pathMatchesGlob("my.env.local", "**/.env.*")).toBe(false);
  });

  it("* stays within a segment; ** crosses segments", () => {
    expect(pathMatchesGlob("src/app.ts", "src/*.ts")).toBe(true);
    expect(pathMatchesGlob("src/x/app.ts", "src/*.ts")).toBe(false);
    expect(pathMatchesGlob("src/x/app.ts", "src/**/*.ts")).toBe(true);
    expect(pathMatchesGlob("tests/fixtures/a.txt", "tests/fixtures/**")).toBe(true);
  });

  it("**/*.pem matches keys at any depth, not arbitrary .pem-suffixed names mid-path", () => {
    expect(pathMatchesGlob("certs/server.pem", "**/*.pem")).toBe(true);
    expect(pathMatchesGlob("server.pem", "**/*.pem")).toBe(true);
    expect(pathMatchesGlob("notes.txt", "**/*.pem")).toBe(false);
  });
});

describe("sensitivePathMatch — real .env only", () => {
  it("flags real sensitive files", () => {
    expect(sensitivePathMatch("/proj/.env")).toBeDefined();
    expect(sensitivePathMatch("/proj/.env.local")).toBeDefined();
    expect(sensitivePathMatch("/home/u/.ssh/id_rsa")).toBeDefined();
  });

  it("does NOT flag ordinary files that merely end in .env", () => {
    expect(sensitivePathMatch("/proj/restored.env")).toBeUndefined();
    expect(sensitivePathMatch("/proj/production.env")).toBeUndefined();
  });

  it("keeps exempting .env.example and friends", () => {
    expect(sensitivePathMatch("/proj/.env.example")).toBeUndefined();
    expect(sensitivePathMatch("/proj/.env.sample")).toBeUndefined();
  });
});

describe("commandTouchesSensitivePath — read commands only", () => {
  it("denies reads of sensitive files", () => {
    expect(commandTouchesSensitivePath("cat .env")).toBe(".env");
    expect(commandTouchesSensitivePath("head -n5 ~/.aws/credentials")).toBeDefined();
    expect(commandTouchesSensitivePath("ls src && cat /proj/.env | grep KEY")).toBeDefined();
  });

  it("does NOT deny WRITING to an env-suffixed file (restore target)", () => {
    expect(commandTouchesSensitivePath("echo 'CI_TOKEN=x' > restored.env")).toBeUndefined();
    expect(commandTouchesSensitivePath("printf 'K=v\\n' > production.env")).toBeUndefined();
  });

  it("does NOT deny innocuous commands", () => {
    expect(commandTouchesSensitivePath("ls -la src/")).toBeUndefined();
    expect(commandTouchesSensitivePath("git status")).toBeUndefined();
    expect(commandTouchesSensitivePath("npm run build")).toBeUndefined();
  });
});
