# Threat Model

AnchorShield's security goal is narrow: prove that a Stellar action satisfied a configured eligibility policy at execution time while minimizing identity disclosure.

## Assumptions

- Issuers are trusted to perform off-chain KYC and publish honest credential roots.
- Users keep credential secrets and witnesses private.
- Soroban contracts and the configured verifier key enforce the public statement.
- Testnet issuer keys, voucher keys, and publisher balances are operational dependencies.

## Threats

| Threat                                            | Mitigation                                                                                                                                                                                                                  | Status   |
| ------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| Proof replay across actions                       | `action_binding`, action fields, and packet hash are public signals checked by the gate.                                                                                                                                    | Done     |
| Double use of one proof                           | Shared nullifier registry rejects reused nullifiers.                                                                                                                                                                        | Done     |
| Amount, asset, recipient, or action id tamper     | `gate_payment` and `attest_for_mint` compare public signals to transaction args.                                                                                                                                            | Done     |
| Frontend lies about policy                        | Contracts load policy fields and root commitments on-chain.                                                                                                                                                                 | Done     |
| Disclosure packet altered                         | Packet hash is bound into the proof and emitted in events.                                                                                                                                                                  | Done     |
| Credential expiry ignored                         | Circuit enforces issued/expires window; attestation TTL is capped.                                                                                                                                                          | Done     |
| Credential revocation bypass                      | Circuit proves non-membership against the committed revocation root.                                                                                                                                                        | Done     |
| Deny-list bypass                                  | Circuit proves non-membership against the committed sanctions root.                                                                                                                                                         | Done     |
| VK replaced after deployment                      | Verifier stores circuit/version VK and freezes it after configuration.                                                                                                                                                      | Done     |
| Recipient/token redirect by admin                 | Payment mappings are write-once per id.                                                                                                                                                                                     | Done     |
| RWA mint not tied to proof action                 | `attest_for_mint` authorizes a specific asset, amount, recipient, action id, and terms hash; adapter consumes it once.                                                                                                      | Done     |
| Raw identity leaks on-chain                       | On-chain data is limited to proof signals, roots, hashes, nullifiers, action data, and events.                                                                                                                              | Done     |
| Issuer links wallet to Sumsub applicant           | Blind voucher flow lets a random KYC session receive an RSA-FDH blind signature and later enroll by commitment without a wallet proof. Legacy wallet-bound enroll remains a fallback only when vouchers are not configured. | Done     |
| Tiny anonymity set deanonymizes early users       | Issuer roots carry member counts; gates enforce `min_credential_members` and emit low-set warnings below 32.                                                                                                                | Done     |
| KYC callback replay or forgery                    | Sumsub webhook receiver verifies HMAC over the raw body with timing-safe compare and dedups raw-body digests.                                                                                                               | Done     |
| Issuer metadata SSRF                              | Metadata fetch rejects credentials, redirects, private/link-local IPs, over-large responses, and non-allowlisted fields.                                                                                                    | Done     |
| Root publisher silently stalls                    | KYC/signer expose health and Prometheus metrics; signer can monitor publisher XLM balance; root publisher refuses divergent pre-state when `expected_previous_roots` is present.                                            | Done     |
| Issuer publishes bad roots without accountability | Issuer registry supports token-backed issuer stake, admin/governance slashing, and reputation records.                                                                                                                      | Done     |
| Admin key compromise                              | Testnet uses a single admin address. Multisig/timelock governance is required before mainnet.                                                                                                                               | Planned  |
| Blind issuance crypto flaw                        | RSA-FDH blind issuance is hand-rolled and needs independent crypto review before mainnet.                                                                                                                                   | Planned  |
| Production ceremony compromise                    | Current ceremony is autonomous-tier. Independent multi-party ceremony is required before mainnet.                                                                                                                           | Planned  |
| Real KYC/anchor custody failure                   | Current KYC/anchor data is mock. Production pilots need provider due diligence and custody design.                                                                                                                          | Planned  |
| Disclosure-vault key compromise                   | Current vault is local demo evidence. Hosted vault key custody is deferred.                                                                                                                                                 | Planned  |
| Relayer/front-running abuse                       | No relayer is implemented. Add caller/source binding before relayer support.                                                                                                                                                | Deferred |

## Data Disclosure Boundary

Public:

- Credential root
- Packet/terms hash
- Nullifier
- Action binding
- Policy and action fields
- Sanctions and revocation roots
- Contract events and transaction metadata

Private:

- Raw KYC attributes
- User secret
- Merkle membership path
- Deny-list and revocation low-leaf witnesses
- Raw Travel-Rule packet, unless disclosed through the vault artifact
- Sumsub applicant id and voucher session linkage

## Mainnet Gate

Mainnet is blocked until the planned items above are implemented, independently reviewed, and explicitly approved for deployment.
