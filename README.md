# AnchorShield

ZK compliance gates for Stellar payments and RWAs.

AnchorShield provides cryptographic evidence that a Stellar action satisfied a configured eligibility policy at the time of execution. Users prove KYC status, corridor eligibility, freshness, deny-list absence, revocation absence, and action binding without putting raw identity data on-chain.

Live demo: https://anchorshield.gudman.xyz

Submission video: pending user recording.

## What Works Now

- Browser Groth16 proving for payment and RWA witnesses.
- Stellar testnet proof verification through a frozen Groth16 verifier contract.
- Action-bound `gate_payment.verify_and_pay` execution against the native SAC on testnet.
- Action-bound RWA mint authorization through `identity_verifier.attest_for_mint`, consumed once by `rwa_compliance_adapter` during an OZ SEP-57 token mint.
- On-chain issuer, policy, nullifier, verifier, payment gate, identity verifier, and RWA compliance adapter contracts.
- In-circuit sanctions deny-list and credential revocation non-membership with roots committed on-chain.
- Issuer ops workflow for OFAC sync, root rotation reports, and stale-root checks.
- Monitoring/indexer alerts for root changes, duplicate nullifiers, invalid proofs, and webhook delivery.
- Dedicated governance contract for signer-threshold, timelocked admin actions and emergency pause/revoke paths.
- Freighter-compatible wallet E2E harness with an injected signer.
- Encrypted Travel-Rule disclosure artifact, local disclosure vault, compliance event index, and auditor/issuer/anchor/RWA dashboards.
- Generated TypeScript bindings, local SDK helpers, and CLI inspection commands.

## Real vs Mock

| Surface | Status |
| --- | --- |
| ZK proof generation | Real Groth16 proof generated from `circuits/eligibility.circom`. |
| On-chain proof verification | Real Soroban verifier on Stellar testnet. |
| Payment execution | Real testnet SAC transfer through `gate_payment.verify_and_pay`. |
| RWA mint authorization | Real testnet authorization and OZ token mint flow; issuer/operator still controls the mint call. |
| Credential source | Mock credential attributes and local fixtures, not a live KYC provider. |
| Sanctions and revocation | Real in-circuit non-membership against committed demo roots. The lists are mock/demo data. |
| SEP-10/31/38 anchor | Mock adapter artifact and dashboard, not a live regulated anchor. |
| Disclosure vault | Local encrypted evidence artifact and grant log, not a hosted production vault. |
| Mainnet | Not deployed. Mainnet requires explicit approval, independent review, and a production ceremony. |

## Why ZK Is Load-Bearing

The payment gate cannot execute without a valid proof. `gate_payment.verify_and_pay` checks the Groth16 proof, policy fields, committed roots, action fields, packet hash, epoch, and nullifier before transferring tokens. A bad proof fails with `InvalidProof`; a reused proof fails through the nullifier registry.

The public statement is limited to proof signals, action data, committed roots, packet hash, nullifier, and action binding. Private credential fields and Merkle witnesses stay off-chain.

## Live Testnet Artifacts

| Artifact | ID / tx |
| --- | --- |
| Verifier | [`CC6SWCQS...2L2I7OCH`](https://stellar.expert/explorer/testnet/contract/CC6SWCQSMNALXV6AUV67I24BQDBSAE33BRQCTMXHGAZKBDVE2L2I7OCH) |
| Issuer registry | [`CDH4LER4...VM5TW7R4`](https://stellar.expert/explorer/testnet/contract/CDH4LER4DMTKKQPBRJNYUJJMFYEDETODHRV7T5VNGBCSGNKRVM5TW7R4) |
| Policy registry | [`CAH5ZI37...ENVKEQFQ`](https://stellar.expert/explorer/testnet/contract/CAH5ZI37PID5IQB7OYB4AU5CJZ7PRLVHVJJ7DDKVP2WHGW4HENVKEQFQ) |
| Nullifier registry | [`CC7KBMVF...YN74BNCT`](https://stellar.expert/explorer/testnet/contract/CC7KBMVFQZ22WH6W6X7D7H6QGY3UIYSE25HL2ZCXQSM5U4BSYN74BNCT) |
| Identity verifier | [`CD647AFZ...OFJKHOB7`](https://stellar.expert/explorer/testnet/contract/CD647AFZSYWVVMBZXNMBIGCADL5FAUDJQDMHJTMVBW5NIGMZOFJKHOB7) |
| RWA compliance adapter | [`CB6KCAGE...2DDJB4NY`](https://stellar.expert/explorer/testnet/contract/CB6KCAGE67EDQWF4K7KQC75ILETMMQK2L5U44AKJ77E7QJS42DDJB4NY) |
| Payment gate | [`CCS7UJWD...T47F5U3R`](https://stellar.expert/explorer/testnet/contract/CCS7UJWD6OP2DGKEGLUCI55SROUC4A3XJ3G4QDQN35HYV3CNT47F5U3R) |
| OZ RWA token | [`CBYALFSE...KIPRHGXT`](https://stellar.expert/explorer/testnet/contract/CBYALFSEIXBLBM23IS4EQMVJXQZYGZNGMDI6NAV3TR7U2JESKIPRHGXT) |
| Payment tx | [`6fea602f...f746b0ae`](https://stellar.expert/explorer/testnet/tx/6fea602fdb2eaf59426271ce17fac7dbc9ed6a04331b5eef34bb4e33f746b0ae) |
| RWA authorization tx | [`fc417569...e95123f2`](https://stellar.expert/explorer/testnet/tx/fc4175698c3a0f8a499f3ce32dd8357169842f6492e291811976bc5fe95123f2) |
| RWA mint tx | [`fca63abf...1d883b3`](https://stellar.expert/explorer/testnet/tx/fca63abfc08dfaf43b4164d876fbde49e4c5c5171bf332a5c92512cbe1d883b3) |

Full deployment JSON is in `deployments/testnet-hardened.json`.

## Quickstart

```bash
npm install
npm run m1:circuit
npm run m5:verify
npm run m6:sdk
npm run m6:cli
npm run issuer:ops:test
npm run monitor:test
npm run wallet:e2e
```

Run the browser demo locally:

```bash
npm run m3:web
```

Open `http://localhost:4173`.

Inspect proof signals and event data:

```bash
node packages/cli/anchorshield.js inspect-public --public testdata/eligibility/public.json
node packages/cli/anchorshield.js validate-action --input testdata/eligibility/input.valid.json --public testdata/eligibility/public.json
node packages/cli/anchorshield.js events --file apps/web/data/compliance-events.json
```

## Security And Limitations

- Ceremony status: autonomous-tier Groth16 ceremony, not an independent production ceremony.
- Verifier governance: the testnet verifier stores a circuit/versioned VK and freezes it after deployment.
- Admin model: source now includes `anchorshield-governance`, but live testnet/mainnet cutover still requires the current admin secret and explicit approval.
- Credential source: demo credentials and deny/revocation lists are mock data.
- Anchor integration: SEP-10/31/38 flow is a deterministic mock adapter.
- Deployment: testnet only. No mainnet deployment, package publish, or external submission is performed without explicit approval.

See `docs/THREAT_MODEL.md`, `docs/SECURITY_REVIEW.md`, `docs/CEREMONY.md`, `docs/SDK.md`, `docs/GOVERNANCE.md`, `docs/OPERATIONS.md`, `docs/WALLET_E2E.md`, `docs/PUBLISH_CHECKLIST.md`, `docs/STRETCH.md`, `docs/ROADMAP.md`, and `docs/DEVIATIONS.md` for the detailed scope.
