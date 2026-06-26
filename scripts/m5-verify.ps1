$ErrorActionPreference = "Stop"

$repo = (Get-Location).Path
$drive = $repo.Substring(0, 1).ToLowerInvariant()
$rest = $repo.Substring(2).Replace("\", "/")
$wslRepo = "/mnt/$drive$rest"

node --check apps/web/assets/app.js
node --check services/disclosure/disclosure.js
node --check services/indexer/build-index.js
node -e "for (const p of ['package.json','deployments/testnet.json','apps/web/data/compliance-events.json','apps/web/data/disclosure-summary.json']) { JSON.parse(require('fs').readFileSync(p,'utf8')); console.log(p + ' ok'); }"
npm audit --audit-level=high
npm run m2:circuit
npm run m4:disclosure
npm run m4:index
wsl bash -lc "cd '$wslRepo/tools/groth16-json-converter' && cargo test -- --nocapture"
wsl bash -lc "cd '$wslRepo/contracts/gate_payment' && cargo test -- --nocapture"
wsl bash -lc "cd '$wslRepo/contracts/gate_rwa' && cargo test -- --nocapture"
