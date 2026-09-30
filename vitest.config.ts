import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Fixtures hold fake tokens and agent-hook stdin payloads consumed by the
    // tests — never collect tests from that tree.
    exclude: [...configDefaults.exclude, "tests/fixtures/**"],
    coverage: {
      include: ["src/**/*.ts"],
      // Generated from the vendored gitleaks config; exercised through the scanner.
      exclude: ["src/engine/rules.gen.ts"],
      // A floor, not a target: CI fails if coverage of the firewall regresses.
      thresholds: { lines: 80, statements: 78, functions: 85, branches: 70 },
    },
  },
});
