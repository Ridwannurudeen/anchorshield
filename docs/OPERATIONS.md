# Production Operations

## Issuer Ops

Run a deterministic root rotation from the current roster, revocation list, and OFAC data:

```bash
npm run issuer:ops
```

Outputs:

- `services/issuer/out/issuance.json`
- `services/issuer/out/rotation-report.json`
- `services/issuer/out/ops-status.json`

Use `npm run issuer:ops -- --sync` only when the environment can fetch the official OFAC `sdn.csv`. The test path uses a mocked fetch:

```bash
npm run issuer:ops:test
```

Root publishing remains separate and approval-gated:

```bash
npm run issuer:publish-roots
ANCHORSHIELD_STELLAR_SOURCE=anchorshield-admin ANCHORSHIELD_ROOT_PUBLISH_APPROVED=1 npm run issuer:publish-roots -- --execute
npm run issuer:publish-roots -- --verify
```

The source identity must be imported locally first with the live admin secret for
`GAJJW5XC23IRZXGY2F36JP4GDFSQ4A65FTZLWCO4EA4JKYZGHEKZJ35U`. The Stellar CLI supports
interactive import with `stellar keys add anchorshield-admin --secret-key`; do not commit or
paste the secret into any repo file. After execution, `--verify` writes
`services/issuer/out/root-publish-report.json` only if the on-chain root getters match the
issuer output roots.

Fresh issuance files include `expected_previous_roots` from deployment metadata. During
`--execute`, `services/issuer/publish-roots.js` reads the current on-chain roots first and refuses
to publish if they do not match that expected pre-state. If this trips, stop and reconcile the
issuer state instead of overwriting chain state.

All human-gated production blockers can be checked together:

```bash
npm run bucket-b:preflight
```

## Monitoring

The monitor reads normalized event fixtures or indexed event JSON, checks root changes, duplicate nullifiers, invalid proofs, and root freshness, then emits log alerts and optionally posts a webhook:

```bash
npm run monitor:check
ANCHORSHIELD_ALERT_WEBHOOK_URL=https://example.test/hooks/anchorshield npm run monitor:check
```

Deterministic alert tests:

```bash
npm run monitor:test
```

KYC backend health and metrics:

```bash
curl -s http://127.0.0.1:3092/api/kyc/healthz
curl -s http://127.0.0.1:3092/api/kyc/metrics
```

Signer health and metrics:

```bash
curl -H "Authorization: Bearer $SIGNER_TOKEN" http://127.0.0.1:3099/healthz
curl -H "Authorization: Bearer $SIGNER_TOKEN" http://127.0.0.1:3099/metrics
```

Set `ANCHORSHIELD_PUBLISHER_BALANCE_MONITOR=1` on the signer to emit publisher XLM balance
metrics. Defaults are warning below 50 XLM and error below 10 XLM; override with
`ANCHORSHIELD_PUBLISHER_BALANCE_WARN_XLM` and `ANCHORSHIELD_PUBLISHER_BALANCE_ERROR_XLM`.

## Blind Voucher Issuance

Generate a voucher key outside the repo and load it by file path:

```bash
node scripts/gen-voucher-key.mjs /etc/anchorshield-kyc/voucher-rsa.pem
```

Set:

- `VOUCHER_RSA_PRIVATE_KEY_FILE=/etc/anchorshield-kyc/voucher-rsa.pem`
- `VOUCHER_TEMPLATE_HMAC_KEY=<random 32+ byte secret>`

The browser blinds the credential leaf locally, the backend signs only the blinded value, and
enrollment verifies the unblinded signature without receiving a wallet proof. This RSA-FDH flow is
for testnet until externally reviewed.

## Sumsub Webhook

Configure `SUMSUB_WEBHOOK_SECRET` and route Sumsub callbacks to:

```text
POST /api/kyc/webhook
```

The receiver verifies `x-payload-digest` over the raw body, supports `HMAC_SHA1_HEX`,
`HMAC_SHA256_HEX`, and `HMAC_SHA512_HEX`, and dedups replayed raw-body digests.

## Web And KYC Proxy Headers

The static web artifact carries a meta CSP and SRI hashes, and production nginx should also send
the same CSP as a response header. The KYC backend rate limiter trusts `X-Real-IP` only from the
loopback nginx proxy, so nginx must overwrite client-supplied forwarding headers:

```nginx
add_header Content-Security-Policy "default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; script-src 'self' https://unpkg.com https://static.sumsub.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob: https://*.sumsub.com; media-src 'self' blob: https://*.sumsub.com; connect-src 'self' https://soroban-testnet.stellar.org https://testanchor.stellar.org https://api.sumsub.com https://*.sumsub.com wss://*.sumsub.com; frame-src 'self' https://static.sumsub.com https://*.sumsub.com; worker-src 'self' blob:; frame-ancestors 'none'" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=*, camera=*" always;

location /api/kyc/ {
    proxy_pass http://127.0.0.1:3092;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

The `Permissions-Policy` line is required for the Sumsub liveness step on `/issuer`. A
`camera=()` value disables the camera feature at the page level, which sits above the browser/OS
permission prompt — the Sumsub WebSDK iframe then fails `getUserMedia` with
"Failed to acquire camera" even after the user clicks Allow. Camera/microphone are safe to open
because CSP `frame-src` already restricts embedded frames to `'self'` and `*.sumsub.com`. This
header is set on the nginx vhost only (not baked into the static artifact), so it survives a web
redeploy but is not captured by `git` — re-apply it if the vhost is rebuilt from scratch.

## Governance

Admin migration and timelock details are in `docs/GOVERNANCE.md`. Mainnet cutover requires the live admin secret and explicit user approval.

## Wallet E2E

Automated Freighter-compatible mock signer:

```bash
npm run wallet:e2e
```

Manual Freighter steps are in `docs/WALLET_E2E.md`.

## Benchmarks

Capture Node proof latency, browser timing input, and testnet fee data:

```bash
npm run benchmarks -- --browser-ms=<measured_browser_ms>
```

Latest measurements are in `docs/BENCHMARKS.md` and `docs/benchmarks/latest.json`.
