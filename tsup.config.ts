import { defineConfig } from "tsup";

// Bundles the TypeScript sources into two single, dependency-free ESM scripts:
//   scripts/secretgate.mjs          — the CLI + hook entrypoint every agent invokes
//   scripts/secretgate-opencode.mjs — the OpenCode plugin (imports the engine in-process)
// No `npm install` is required at hook-run time: hooks fire on EVERY prompt and
// tool call, so the bundle must start fast (no module resolution) and never
// depend on node_modules being present. `scripts/copy-bundle.mjs` mirrors the
// CLI bundle into the skill dir; CI's `check:build` asserts reproducibility.
// Target is node18 — a hook runs on whatever Node the user has, so the floor
// stays as low as the syntax we use allows.
export default defineConfig({
  entry: {
    secretgate: "src/cli.ts",
    "secretgate-opencode": "src/adapters/opencode-plugin.ts",
  },
  outDir: "scripts",
  format: ["esm"],
  outExtension: () => ({ js: ".mjs" }),
  target: "node18",
  platform: "node",
  bundle: true,
  clean: false,
  minify: false,
  splitting: false,
  sourcemap: false,
  banner: { js: "#!/usr/bin/env node" },
});
