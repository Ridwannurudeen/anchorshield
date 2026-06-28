// Portable replacement for scripts/m5-verify.ps1. Runs the full local
// verification: JS lint/JSON checks, audit, circuit smoke, off-chain services,
// and the Rust contract + converter test suites. Works on Linux/macOS (CI) and
// Windows.
import { run, tool } from "./_sh.mjs";

run("node --check apps/web/assets/app.js");
run("node --check services/disclosure/disclosure.js");
run("node --check services/disclosure/vault.js");
run("node --check services/disclosure/vault.test.js");
run("node --check services/indexer/build-index.js");
run("node --check services/mock-anchor/sep-adapter.js");
run("node --check services/mock-anchor/sep-adapter.test.js");
run(
  "node -e \"for (const p of ['package.json','deployments/testnet-hardened.json','apps/web/data/deployments.json','apps/web/data/compliance-events.json','apps/web/data/disclosure-summary.json','apps/web/data/disclosure-vault.json','apps/web/data/mock-anchor.json']) { if (require('fs').existsSync(p)) { JSON.parse(require('fs').readFileSync(p,'utf8')); console.log(p+' ok'); } }\"",
);
run("npm audit --audit-level=high");

tool("node scripts/m1-circuit-smoke.js");

run("node services/disclosure/disclosure.js");
run("node services/disclosure/vault.test.js");
run("node services/disclosure/vault.js");
run("node services/indexer/build-index.js");
run("node services/mock-anchor/sep-adapter.test.js");
run("node services/mock-anchor/sep-adapter.js");

tool("cargo test", "tools/groth16-json-converter");
tool("cargo test --workspace");

console.log("\nm5:verify OK");
