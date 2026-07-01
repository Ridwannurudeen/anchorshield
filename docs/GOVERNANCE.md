# Governance

AnchorShield uses a dedicated Soroban governance contract for production admin control. The existing live admin remains required for the one-time cutover, but each governed contract uses two-step admin transfer: the live admin stages `pending_admin` with `transfer_admin`, then governance accepts with an `AcceptAdmin` proposal.

## Model

- Normal path: signer proposes, signer set reaches `threshold`, timelock expires, anyone executes.
- Emergency path: only `Pause`, `Unpause`, and `RevokeGate` actions can use `emergency_threshold` plus `emergency_delay_ledgers`.
- Config changes are themselves governance proposals through `UpdateConfig`.
- Root rotations are governed actions against `issuer_registry`: `SetCredentialRoot`, `SetSanctionsRoot`, and `SetRevocationRoot`.
- Issuer accountability actions are governed through `SlashIssuer` and `SetIssuerReputation`.
- Gates expose a pause-only role for per-policy or per-issuer halts. The pauser can halt scoped traffic; admin/governance unpauses.

## Testnet Rehearsal

1. Deploy `anchorshield_governance.wasm`.
2. Initialize it with a signer set and delays matching `deployments/governance.config.example.json`.
3. From the current admin identity, call `transfer_admin --new_admin <GOVERNANCE_CONTRACT_ID>` on:
   - verifier
   - issuer_registry
   - policy_registry
   - nullifier_registry
   - identity_verifier
   - rwa_compliance_adapter
   - gate_payment
   - gate_rwa
4. Verify each contract still reports the old `admin()` and now reports `pending_admin() == <GOVERNANCE_CONTRACT_ID>`.
5. Through governance, propose and execute `AcceptAdmin(<contract_id>)` for each governed contract.
6. Verify each contract reports `admin() == <GOVERNANCE_CONTRACT_ID>` and `pending_admin() == None`.
7. Propose and execute a no-op root rehearsal on a fresh testnet issuer registry using a non-production root.
8. Propose and execute an emergency `Pause` on a fresh testnet gate, then `Unpause`.
9. Set a gate pauser on a fresh testnet gate, pause one policy, verify only that policy halts, then unpause through admin/governance.

Live cutover is gated on the live admin secret for `GAJJW5XC23IRZXGY2F36JP4GDFSQ4A65FTZLWCO4EA4JKYZGHEKZJ35U`. Do not run the live cutover until the user provides that secret and explicitly approves the execution.
