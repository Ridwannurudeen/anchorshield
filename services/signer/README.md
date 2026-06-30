# AnchorShield Root Signer

The signer keeps enrollment root publishing out of the internet-facing KYC backend.
It binds to `127.0.0.1`, requires `SIGNER_TOKEN`, recomputes the credential root from
the enrollment state, asserts the local Stellar signing identity resolves to the
deployed admin, and dry-runs unless `ANCHORSHIELD_ROOT_PUBLISH_APPROVED=1`.

## Threat Model

This is an isolated software signer on the same host, not an HSM and not a
threshold signer. It removes the issuer admin key from the web tier and prevents
forged caller-supplied roots because the signer derives the root from
`buildEnrollmentView`. It does not protect against host root compromise.

The upgrade path is a separate signing host, KMS-backed key policy, or governance
multisig/threshold approval before mainnet.

## Endpoints

- `GET /healthz` returns `{ ok, approved, admin }`.
- `POST /publish-credential-root` accepts only `{ issuerId }`. Any caller root is
  ignored.

Both endpoints require `Authorization: Bearer <SIGNER_TOKEN>` and loopback
access. The signer maps Stellar command failures to `502`.

## Environment

- `SIGNER_TOKEN`: required bearer token shared with the KYC backend.
- `SIGNER_PORT`: optional, defaults to `3099`.
- `ANCHORSHIELD_STELLAR_SOURCE`: signer-only Stellar identity name or address.
- `ANCHORSHIELD_ENROLLMENT_STATE_PATH`: shared enrollment state path. Defaults to
  `services/issuer/out/enrollments.json`.
- `ANCHORSHIELD_ROOT_PUBLISH_APPROVED`: set to `1` only after explicit approval
  to run the `stellar contract invoke set_root` command.

The KYC backend should have `SIGNER_TOKEN`, `SIGNER_PORT`, and
`ANCHORSHIELD_ENROLLMENT_STATE_PATH`; it should not have
`ANCHORSHIELD_STELLAR_SOURCE` or a readable Stellar keystore.
