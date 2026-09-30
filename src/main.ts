import { run } from "./cli.js";

// Process entrypoint of the Node bundle (scripts/secretgate.mjs). Unconditional
// on purpose: an "am I the entrypoint?" guard that misfires — symlinked homes,
// a compiled binary's virtual paths — makes a hook exit with no output, which
// the agent reads as "no objection" (fail-open).
run(process.argv.slice(2), {
  stdout: (s) => process.stdout.write(s),
  stderr: (s) => process.stderr.write(s),
}).then((code) => {
  process.exitCode = code;
});
