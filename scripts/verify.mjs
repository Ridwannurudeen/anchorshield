// Portable replacement for scripts/m5-verify.ps1. Runs the full local
// verification: JS lint/JSON checks, audit, circuit smoke, off-chain services,
// and the Rust contract + converter test suites. Works on Linux/macOS (CI) and
// Windows.
import { run, tool } from "./_sh.mjs";

run(
  "node -e \"const fs=require('fs'); const banned=['apps/web/data/payment-input.json','apps/web/data/rwa-input.json','apps/web/data/payment-proof-pool.json']; const found=banned.filter((p)=>fs.existsSync(p)); if(found.length){ console.error('web artifact exposes private proof material: '+found.join(', ')); process.exit(1); } console.log('web artifact proof-material guard ok');\"",
);

run("node --check scripts/check-web-security.mjs");
run("node --check scripts/build-poseidon-web-data.mjs");
run("node --check apps/web/assets/app.js");
run("node --check apps/web/assets/blind.js");
run("node --check services/disclosure/disclosure.js");
run("node --check services/disclosure/build-web-packet.js");
run("node --check services/disclosure/vault.js");
run("node --check services/disclosure/vault.test.js");
run("node --check services/indexer/build-index.js");
run("node --check services/issuer/issue.js");
run("node --check services/issuer/enrollment-store.js");
run("node --check services/issuer/lib/ofac.js");
run("node --check services/issuer/lib/zk-tree.js");
run("node --check services/issuer/ofac-sync.js");
run("node --check services/issuer/ops.js");
run("node --check services/issuer/publish-roots.js");
run("node --check services/issuer/test.js");
run("node --check services/kyc-backend/server.js");
run("node --check services/kyc-backend/blind-voucher.js");
run("node --check services/kyc-backend/issuer-directory.js");
run("node --check services/kyc-backend/server.test.js");
run("node --check services/signer/client.js");
run("node --check services/signer/signer.js");
run("node --check services/signer/signer.test.js");
run("node --check services/anchor/sep-client.js");
run("node --check services/anchor/sep-client.test.js");
run("node --check services/monitoring/monitor.js");
run("node --check services/monitoring/monitor.test.js");
run("node --check services/wallet-e2e/freighter-harness.js");
run("node --check services/wallet-e2e/freighter-harness.test.js");
run("node --check services/wallet-e2e/onchain-e2e.mjs");
run("node --check services/wallet-e2e/onchain-e2e.test.mjs");
run("node --check services/mock-anchor/sep-adapter.js");
run("node --check services/mock-anchor/sep-adapter.test.js");
run("node --check scripts/benchmarks.mjs");
run("node --check scripts/bucket-b-preflight.mjs");
run("node --check scripts/bucket-b-gates.test.mjs");
run("node --check scripts/check-web-security.mjs");
run("node --check scripts/gen-voucher-key.mjs");
run("node --check scripts/mainnet-preflight.mjs");
run("node --check scripts/publish-preflight.mjs");
run("node --check scripts/serve-web.mjs");
run("node --check scripts/serve-web.test.mjs");
run("node --check scripts/make-demo-witness.mjs");
run(
  "node -e \"for (const p of ['package.json','deployments/testnet-hardened.json','apps/web/data/deployments.json','apps/web/data/compliance-events.json','apps/web/data/disclosure-summary.json','apps/web/data/disclosure-vault.json','apps/web/data/mock-anchor.json','apps/web/data/poseidon255-t3.json']) { if (require('fs').existsSync(p)) { JSON.parse(require('fs').readFileSync(p,'utf8')); console.log(p+' ok'); } }\"",
);
run("npm audit --audit-level=high");

tool("node scripts/m1-circuit-smoke.js");

run("node services/disclosure/disclosure.js");
run("node services/disclosure/build-web-packet.js");
run("node services/disclosure/vault.test.js");
run("node services/disclosure/vault.js");
run("node services/indexer/build-index.js");
run("node services/issuer/issue.js");
run("node services/issuer/test.js");
run("node services/kyc-backend/server.test.js");
run("node services/signer/signer.test.js");
run("node services/anchor/sep-client.test.js");
run("node services/wallet-e2e/onchain-e2e.test.mjs");
run("node scripts/check-web-security.mjs");
run("node scripts/bucket-b-gates.test.mjs");
run("node scripts/serve-web.test.mjs");
run("node services/mock-anchor/sep-adapter.test.js");
run("node services/mock-anchor/sep-adapter.js");

tool("cargo test", "tools/groth16-json-converter");
tool("cargo test --workspace");

console.log("\nm5:verify OK");
