// Dev-only: lets Node run the TypeScript sources directly (type stripping,
// Node >= 22.18), resolving the sources' `./x.js` imports to `./x.ts`. The
// verifier's child process uses it when secretgate itself runs from its
// sources (the tests); the bundle and the binary never load it.
//   node --import ./scripts/ts-resolve.mjs src/main.ts <command>
import * as nodeModule from "node:module";

nodeModule.registerHooks({
  resolve(spec, ctx, next) {
    try {
      return next(spec, ctx);
    } catch (err) {
      if (spec.startsWith(".") && spec.endsWith(".js")) return next(`${spec.slice(0, -3)}.ts`, ctx);
      throw err;
    }
  },
});
