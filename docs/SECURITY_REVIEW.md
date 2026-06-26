# Security Review

## Scope Reviewed

- `circuits/eligibility.circom`
- `contracts/gate_payment`
- `contracts/gate_rwa`
- `tools/groth16-json-converter`
- `services/disclosure`
- `services/indexer`
- `apps/web`

## Passing Checks

| Area | Check | Status |
| --- | --- | --- |
| Circuit | invalid KYC, sanctions, country, amount, expiry, investor witnesses reject | Pass |
| Circuit | action-binding public-input mutation rejects | Pass |
| Converter | M0, M1, M2 golden fixtures convert to Soroban CLI layout | Pass |
| Payment gate | valid proof pays, wrong action rejects, wrong policy rejects, packet hash mismatch rejects, reused nullifier rejects, rotated root rejects | Pass |
| RWA gate | valid proof transfers, payment proof rejects, wrong action rejects, wrong policy rejects, terms hash mismatch rejects, reused nullifier rejects, rotated root rejects | Pass |
| Disclosure | encrypted packet decrypts and verifies against payment proof public `packet_hash` | Pass |
| Indexer | M1/M2 testnet events normalize into no-PII dashboard data | Pass |
| Browser | local and public browser proofs generate and verify with `snarkjs` | Pass |

## Primary Findings

### Event packet hash is joined off-chain

Severity: Medium

The M1 `PaymentApproved` event does not include `packet_hash`. M4 joins the event to the known proof public signals to render the packet hash in the dashboard.

Resolution: documented in `docs/DEVIATIONS.md`. Before mainnet, emit packet/terms hash directly from both gates.

### Demo proving key is not a production ceremony

Severity: High before mainnet

The current zkey is a smoke setup artifact. It is acceptable for testnet/demo proving, not for production.

Resolution: production ceremony requirements are documented in `docs/CEREMONY.md`.

### Admin control is single-address

Severity: High before mainnet

The current gates store one `Address` admin. Soroban allows that address to be a contract, but no multisig/timelock/pause admin contract is implemented in this repo yet.

Resolution: do not deploy mainnet until a multisig/timelock/pause admin path is implemented and tested.

### Browser does not submit Soroban transactions

Severity: Medium

The M3 app generates and verifies proofs in-browser, then links to already executed testnet transactions. It does not build/sign/send Soroban invoke transactions.

Resolution: SDK/CLI work in M6 must own browser/server transaction assembly.

## Mainnet Blockers

- Production multi-party ceremony not yet performed.
- Packet/terms hash not emitted directly in current approval events.
- Admin multisig/timelock/pause not implemented.
- Mainnet deployment requires explicit user approval.
- Package publishing requires explicit user approval.
