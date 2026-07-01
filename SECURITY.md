# Security Policy

## Scope

Security reports are in scope for:

- Soroban contracts under `contracts/`
- Circuits under `circuits/`
- KYC, issuer, signer, monitoring, and anchor services under `services/`
- Public web artifact under `apps/web/`
- SDK, CLI, and bindings under `packages/`

Out of scope:

- Testnet faucet availability
- Sumsub sandbox account availability
- Social engineering, spam, or denial-of-service against public third-party services
- Findings requiring leaked secrets, unless the report also identifies the leak path

## Reporting

Do not open a public issue for a live exploit. Send a private report with:

- Impacted component
- Reproduction steps
- Expected and actual behavior
- Suggested severity
- Whether funds, credentials, secrets, or private witness data are exposed

## Response Targets

| Severity | Examples                                                                    | Target                                                             |
| -------- | --------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| Critical | Forged proof accepted, private key leak, root-publisher takeover            | Acknowledge within 24h; patch or disable affected path immediately |
| High     | KYC bypass, blind-voucher replay, SSRF to private network, nullifier replay | Acknowledge within 48h; patch before next deployment               |
| Medium   | Incorrect monitoring, degraded privacy warning, metadata validation issue   | Acknowledge within 5 business days                                 |
| Low      | Documentation, non-sensitive UI, test-only issues                           | Best effort                                                        |

## Incident Runbook

| Symptom                                   | Likely cause                                                                      | Action                                                                                                                                                                                |
| ----------------------------------------- | --------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Proofs start failing with `RootMismatch`  | Root rotated while users hold stale Merkle paths, or publisher divergence         | Pause affected policy, run `/api/kyc/metrics` and signer `/metrics`, verify current and previous roots, regenerate path, then publish only if `expected_previous_roots` matches chain |
| Proofs accepted from tiny credential set  | Policy `min_credential_members` too low                                           | Raise policy floor, keep frontend warning visible, and do not market the deployment as anonymity-preserving until the floor is met                                                    |
| Root rotation stops                       | Signer not approved, Stellar CLI identity mismatch, low publisher XLM             | Check signer `/healthz`, `/metrics`, publisher balance, systemd logs, then fund publisher or restore signer identity                                                                  |
| KYC status polling disagrees with webhook | Provider delay or forged/replayed callback attempt                                | Trust HMAC-verified raw-body webhook records only; inspect webhook dedup count and Sumsub applicant status                                                                            |
| Metadata directory fails                  | Issuer URI redirects, resolves private IP, is too large, or has invalid fields    | Keep issuer hidden/error-marked; do not bypass SSRF rejection                                                                                                                         |
| Voucher issuance fails after GREEN        | Voucher session spent, RSA key not configured, or local blind verification failed | Restart KYC session; confirm `VOUCHER_RSA_PRIVATE_KEY_FILE` and `VOUCHER_TEMPLATE_HMAC_KEY`; rotate key if compromise is suspected                                                    |
| Nullifier replay alert                    | User resubmitted same proof or replay attempt                                     | Confirm nullifier registry state; no root action needed unless duplicate acceptance is observed                                                                                       |

## Mainnet Gate

Mainnet remains blocked until there is explicit approval, independent contract and circuit review, a production ceremony, a production multisig/timelock admin, and external review of the RSA-FDH blind issuance implementation.
