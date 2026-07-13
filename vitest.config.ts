import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Fixtures hold fake tokens and agent-hook stdin payloads consumed by the
    // tests — never collect tests from that tree.
    exclude: [...configDefaults.exclude, "tests/fixtures/**"],
  },
});
