// Portable replacement for scripts/m5-verify.ps1. Runs the full local
// verification: JS lint/JSON checks, audit, circuit smoke, off-chain services,
// and the Rust contract + converter test suites. Works on Linux/macOS (CI) and
// Windows (bridges the Rust/circom steps to WSL).
import { run, tool } from "./_sh.mjs";

run("node --check apps/web/assets/app.js");
run("node --check services/disclosure/disclosure.js");
run("node --check services/indexer/build-index.js");
run(
  "node -e \"for (const p of ['package.json','deployments/testnet.json','apps/web/data/compliance-events.json','apps/web/data/disclosure-summary.json']) { JSON.parse(require('fs').readFileSync(p,'utf8')); console.log(p+' ok'); }\"",
);
run("npm audit --audit-level=high");

tool("node scripts/m1-circuit-smoke.js");

run("node services/disclosure/disclosure.js");
run("node services/indexer/build-index.js");

tool("cargo test", "tools/groth16-json-converter");
tool("cargo test --workspace");

console.log("\nm5:verify OK");
