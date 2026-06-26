// Portable replacement for scripts/m6-verify.ps1 (pure Node — SDK/CLI/bindings).
import { run } from "./_sh.mjs";

run("node packages/sdk/test.js");
run("node packages/cli/test.js");
run(
  "node -e \"for (const p of ['packages/sdk/package.json','packages/cli/package.json','packages/bindings/gate-payment/package.json','packages/bindings/gate-rwa/package.json']) { JSON.parse(require('fs').readFileSync(p,'utf8')); console.log(p+' ok'); }\"",
);

console.log("\nm6:verify OK");
