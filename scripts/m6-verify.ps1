$ErrorActionPreference = "Stop"

node --check packages/sdk/src/index.js
node --check packages/sdk/test.js
node --check packages/cli/anchorshield.js
node --check packages/cli/test.js

npm run m6:sdk
npm run m6:cli

node -e "for (const p of ['packages/sdk/package.json','packages/cli/package.json','packages/bindings/gate-payment/package.json','packages/bindings/gate-rwa/package.json']) { JSON.parse(require('fs').readFileSync(p,'utf8')); console.log(p + ' ok'); }"
