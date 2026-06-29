# Real Anchor Sandbox

AnchorShield's demo mock anchor remains available for deterministic local proofs, but the
production seam is now `services/anchor/sep-client.js`.

## Scope

The client is intentionally config-driven:

- SEP-10: fetches an anchor web-auth challenge and exchanges a signed challenge for a token.
- SEP-38: requests a price and creates a quote.
- SEP-31: creates and fetches receive transactions.
- AnchorShield proof data is carried as transaction fields:
  - `anchorshield_policy_id`
  - `anchorshield_packet_hash`
  - `anchorshield_action_binding`

No licensed anchor credentials are committed. `services/anchor/anchor.config.example.json`
documents the required sandbox fields.

## Sandbox Flow

1. Run the issuer pipeline:

```bash
npm run ofac:sync
node services/issuer/issue.js
```

2. Obtain a SEP-10 token from the licensed anchor sandbox. The client exposes
   `sep10Challenge` and `sep10Token`, but signing the challenge is wallet/key-management
   specific and must not use committed secrets.

3. Create `services/anchor/anchor.config.json` from the example file.

4. Run:

```bash
node services/anchor/sep-client.js
```

The output is written to `services/anchor/out/sandbox-run.json`, which is ignored because it
can contain partner-specific transaction identifiers.

The client validates that all required fields are present, endpoint URLs are HTTPS, and the
example placeholders have been replaced before it sends sandbox requests.

## Public reference anchor (testanchor.stellar.org)

No licensed partner is required to exercise the seam: the SDF public reference anchor exposes
SEP-10/12/31/38 for open testing. Endpoints are pre-filled in
`services/anchor/anchor.config.testanchor.json` (verified against its live `stellar.toml`:
SEP-31 `/sep31`, SEP-38 `/sep38`, auth `/auth`, KYC `/sep12`; assets include
`stellar:SRT:GCDNJUBQSX7AJWLJACMJ7I4BC3Z47BQUTMHEICZLE6MU4KQBRYG5JY6B`). Run from WSL — the
bash sandbox cannot reach testanchor, but WSL has open network.

Bootstrap the ephemeral fields (token + customer IDs are session-scoped, so never committed):

1. SEP-10 — `GET /auth?account=<G_ADDR>&home_domain=testanchor.stellar.org`, sign the returned
   challenge with the account secret, `POST /auth` with the signed XDR, keep the returned `token`.
2. SEP-12 — with that bearer token, `PUT /sep12/customer` twice (types `sep31-sender` and
   `sep31-receiver`; testanchor accepts dummy KYC values) and keep each returned `id`.
3. Copy `anchor.config.testanchor.json` to `anchor.config.json`; fill `token`, `senderId`,
   `receiverId`, a future `quoteExpiresAt`, and `packetHash`/`actionBinding` (public signals 1
   and 3 from a generated proof's `public.json`).
4. `node services/anchor/sep-client.js` → real `services/anchor/out/sandbox-run.json`.

## Verification

```bash
node services/anchor/sep-client.test.js
```

The test mocks all network calls and verifies request paths, bearer-token propagation,
SEP-38 quote creation, SEP-31 transaction creation/fetching, and AnchorShield proof-field
binding.
