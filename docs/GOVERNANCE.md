# Governance

AnchorShield uses a dedicated Soroban governance contract for production admin control. The existing live admin remains required for the one-time cutover, but after each contract's `transfer_admin` call, signer-approved governance proposals execute admin actions.

## Model

- Normal path: signer proposes, signer set reaches `threshold`, timelock expires, anyone executes.
- Emergency path: only `Pause`, `Unpause`, and `RevokeGate` actions can use `emergency_threshold` plus `emergency_delay_ledgers`.
- Config changes are themselves governance proposals through `UpdateConfig`.
- Root rotations are governed actions against `issuer_registry`: `SetCredentialRoot`, `SetSanctionsRoot`, and `SetRevocationRoot`.

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
4. Propose and execute a no-op root rehearsal on a fresh testnet issuer registry using a non-production root.
5. Propose and execute an emergency `Pause` on a fresh testnet gate, then `Unpause`.

Live cutover is gated on the live admin secret for `GAJJW5XC23IRZXGY2F36JP4GDFSQ4A65FTZLWCO4EA4JKYZGHEKZJ35U`. Do not run the live cutover until the user provides that secret and explicitly approves the execution.
