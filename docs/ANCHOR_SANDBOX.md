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

## Verification

```bash
node services/anchor/sep-client.test.js
```

The test mocks all network calls and verifies request paths, bearer-token propagation,
SEP-38 quote creation, SEP-31 transaction creation/fetching, and AnchorShield proof-field
binding.
