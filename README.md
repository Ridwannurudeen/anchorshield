# AnchorShield

AnchorShield is a zero-knowledge eligibility and compliance gate for Stellar.

Current state:

- M0 reproduced the official Stellar Groth16 verifier on testnet.
- M1 proves a mock credential satisfies one payment policy, verifies the Groth16 proof on Soroban testnet, marks a nullifier, and executes a mock-asset payment.
- M2 proves the same mock credential satisfies a second RWA policy, verifies the Groth16 proof on Soroban testnet, marks a distinct nullifier, and executes a mock RWA transfer.
- M3 ships a browser demo dApp with live in-browser Groth16 proving for both flows, failure checks, wallet detection, and Stellar Expert event links.
- M4 adds encrypted Travel-Rule disclosure verification, indexed compliance events, and an auditor dashboard view with no PII on-chain.
- M5 documents the ceremony/security gates, adds CI, and runs the full local verification suite.
- M6 adds generated TypeScript bindings, a dependency-free local SDK, a CLI, and mainnet/publishing runbooks. Mainnet deploy and npm publishing are not executed without explicit approval.
- Stretch backends were verified but not claimed complete; `docs/STRETCH.md` records the UltraHonk, RISC Zero, sanctions non-membership, and relayer blockers.

The secret is the user's credential fields and Merkle path. The public statement is the credential root, policy/action fields, packet hash, nullifier, and action binding. The circuit is `circuits/eligibility.circom`; the current Soroban verifier gate is `contracts/gate_payment`.

Public demo: `https://preflight.gudman.xyz/anchorshield/`

See `docs/M0.md` through `docs/M6.md`, `docs/SDK.md`, `docs/MAINNET_RUNBOOK.md`, `docs/STRETCH.md`, and `docs/DEVIATIONS.md` for verified commands, tx hashes, and mock scope.
