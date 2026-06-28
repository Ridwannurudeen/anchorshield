# AnchorShield — Master Build Plan

> **AnchorShield** — a zero-knowledge eligibility & compliance access layer for Stellar.
> Users verify once, then privately prove they are eligible to use Stellar-powered financial
> services (remittances, stablecoin payments, regulated/tokenized assets) without exposing
> identity or KYC data on-chain. Soroban contracts verify the proofs before any financial
> action executes.
>
> This document is the single source of truth for the build. It is intentionally ambitious and
> deadline-agnostic: it describes the *robust, production-shaped* system, then phases it so it can
> be built incrementally with a working artifact at the end of every milestone.

---

## 0. How to use this document (READ FIRST — applies to every contributor, human or Codex)

This plan is written to be executed by an autonomous coding agent (Codex) and reviewed by a human lead. The following rules are **non-negotiable** and override any impulse to move fast:

1. **Verify before you build.** Never assume an API, function signature, crate/package version, CLI flag, or host-function name. Confirm it against the actual source: the installed crate, the repo, the lockfile, or the live docs. Every section below that depends on an external interface is tagged **`[VERIFY]`** with what to check. If you cannot verify something, stop and flag it — do not invent it.
2. **Read before you write.** Read the surrounding code and the referenced upstream repos before adding or editing code. Match existing patterns.
3. **Test after every change.** Each task has a Definition of Done that includes a passing test or a reproducible on-chain verification. "Should work" is not done.
4. **One milestone, one working artifact.** Do not start a milestone until the previous one's acceptance criteria pass. Every milestone ends with something demonstrable.
5. **Honest WIP over polished mystery.** If something is mocked, stubbed, or unfinished, say so in the README and in code comments. Never fake a verification.
6. **No secrets in the repo.** Keys, seeds, ceremony toxic waste, issuer private keys — never committed. See §11.

**Reference repos (confirmed to exist as of 2026-06; `[VERIFY]` current state and exact APIs before depending on them):**
- Official Circom/Groth16 Soroban verifier example: `https://github.com/stellar/soroban-examples` → `groth16_verifier/` (uses BLS12-381 host functions; circom 2.2.1 in its source).
- UltraHonk/Noir Soroban verifier: `https://github.com/NethermindEth/rs-soroban-ultrahonk` (transferred from `yugocabrio/`).
- RISC Zero Soroban verifier (router pattern): `https://github.com/NethermindEth/stellar-risc0-verifier`.
- Stellar private-payments PoC (Circom + Groth16 + ASP membership, browser proving): `https://github.com/NethermindEth/stellar-private-payments`.
- OpenZeppelin Stellar contracts (RWA / SEP-57 reference): `https://github.com/OpenZeppelin/stellar-contracts`.
- E2E tutorials (orientation only): `https://jamesbachini.com/circom-on-stellar/`, `/noir-on-stellar/`, `/stellar-risc-zero-games/`.
- Official docs: `https://developers.stellar.org/docs/build/apps/zk` and `/build/apps/privacy`.

---

## 1. Vision, problem, and success criteria

### 1.1 The problem (real, ecosystem-level)
Stellar is built for real-world money movement — stablecoins, anchors (regulated fiat on/off-ramps), cross-border corridors, and tokenized real-world assets (RWAs). Every one of those touchpoints needs to know *something* about the user (KYC status, jurisdiction, accreditation, sanctions status, transaction limits). Today that information is:
- **Re-collected at every anchor/app** (SEP-12 KYC honeypots repeated everywhere),
- **Either exposed on a public ledger or kept in a centralized silo**, and
- **Not reusable** across services.

There is no reusable, privacy-preserving way to prove "I am eligible for this financial action" on Stellar.

### 1.2 The product
AnchorShield is a **reusable ZK access layer**: a credential a user obtains once from a trusted issuer, plus a set of Soroban contracts that verify zero-knowledge proofs of eligibility against on-chain **policies** before allowing a financial action. The ZK is load-bearing: remove it and the gate cannot function.

Demonstrated through two reference "gates" that share one verifier and one credential:
- **Remittance / Travel-Rule gate** (the "AnchorShield payment gate"): a cross-border stablecoin payment executes only if the sender proves KYC-clear, sanctions-clear, allowed-corridor, under-limit, and that an off-chain Travel-Rule packet is cryptographically bound to *this exact payment*.
- **RWA access gate**: a transfer/mint of a regulated SEP-57 (ERC-3643/T-REX-style) token executes only if the holder proves allowed-jurisdiction, KYC-clear, and investor-eligibility — integrating with SEP-57's compliance hook.

### 1.3 Mission alignment (why SDF/judges/investors care)
- **Mission:** SDF's stated mission is equitable access to the global financial system. A reusable private-eligibility layer broadens access (one credential, many services) while letting regulated entities participate.
- **Tech:** turns the raw Protocol 25/26 primitives (BN254 EC ops, Poseidon/Poseidon2, BLS12-381, nullifier-friendly hashing) into a higher-level reusable building block — exactly the "gap between primitives and product" the ecosystem needs closed.
- **Ecosystem:** directly addresses the SEP-12 re-KYC honeypot problem and plugs into SEP-57 regulated assets.
- **Investors:** an access/compliance layer many apps depend on is fundable infrastructure, not a one-off app.

### 1.4 Success criteria (definition of "done" for the whole project)
1. A user obtains a credential from a (mock-but-realistic) issuer; only a commitment hits the chain.
2. The same credential satisfies **two different policies** (payment + RWA) through **one** verifier contract.
3. Proofs are **verified on-chain** on Stellar **testnet** (and **mainnet** for the flagship flow).
4. The five failure paths provably reject: not-eligible, over-limit, wrong jurisdiction/corridor, replayed nullifier, packet/action mismatch.
5. Action-binding is real: a proof for payment A cannot be replayed for payment B.
6. Full test suite (circuits + contracts + e2e) green in CI; trusted-setup ceremony performed and documented; security review completed.
7. SDK + docs let a third-party dev add an AnchorShield gate to their own contract in <1 day.

---

## 2. System architecture

### 2.1 Components (logical)
```
                       ┌─────────────────────────────────────────────┐
                       │              ISSUER LAYER (off-chain)         │
  KYC / anchor /       │  Issuer Service: verifies user, mints a       │
  RWA issuer / gov ───▶│  signed credential, inserts commitment into   │
                       │  a Poseidon Merkle tree, publishes root        │
                       └───────────────┬─────────────────────────────┘
                                       │ credential_root (on-chain)
                                       ▼
  ┌──────────────┐   proof   ┌───────────────────────────────────────┐
  │   USER /      │──────────▶│         ON-CHAIN (Soroban)             │
  │   WALLET      │           │  ┌──────────────────────────────────┐ │
  │  (holds       │           │  │ Issuer Registry (trusted issuers, │ │
  │  credential,  │           │  │   their current credential roots) │ │
  │  proves       │           │  ├──────────────────────────────────┤ │
  │  in-browser)  │           │  │ Policy Registry (policy_id →      │ │
  └──────────────┘           │  │   {required attrs, jurisdiction,  │ │
        ▲                    │  │   limit, sanctions_root, expiry}) │ │
        │                    │  ├──────────────────────────────────┤ │
        │                    │  │ Verifier Router → Groth16 verifier│ │
        │                    │  │   (pluggable: +UltraHonk/+risc0)  │ │
        │                    │  ├──────────────────────────────────┤ │
        │                    │  │ Nullifier Registry (spent set)    │ │
        │                    │  ├──────────────────────────────────┤ │
        │  result/event      │  │ GATES (call the above):           │ │
        └────────────────────│  │  • Payment/Travel-Rule gate       │ │
                             │  │  • RWA/SEP-57 access gate          │ │
                             │  └──────────────────────────────────┘ │
                             └───────────────────────────────────────┘
                                       │ events
                                       ▼
                       ┌─────────────────────────────────────────────┐
                       │  OFF-CHAIN SERVICES: indexer, compliance      │
                       │  dashboard (auditor view-keys), issuer console│
                       └─────────────────────────────────────────────┘
```

### 2.2 Trust model
- **Issuers** are trusted to attest credential attributes truthfully. Multiple issuers supported via the Issuer Registry. The chain trusts an issuer's published root; it does not see raw attributes.
- **Users** custody their own credential secret; proofs are generated client-side (the secret never leaves the device).
- **Verifier/contracts** are trustless: anyone can verify a proof; the contract enforces policy + action-binding + nullifier uniqueness.
- **Auditors/regulators** can be granted selective disclosure via view-keys (see §3.7), never blanket on-chain exposure.

### 2.3 Threat model (must be addressed; see §9 for mitigations)
- Proof replay across actions → **action-binding** (public inputs == on-chain action args).
- Double-spend of a one-time eligibility → **nullifier registry**.
- Forged credentials → **issuer signature + Merkle membership under a registered root**.
- Stale/revoked credentials → **epoch roots + revocation** (§3.6).
- Front-running a submitted proof → **bind proof to caller/recipient**, not just amount (§9).
- Sanctions list integrity → **on-chain committed `sanctions_root`** with in-circuit non-membership in the hardened build.
- Trusted-setup compromise (Groth16) → **multi-party ceremony**, documented, toxic waste destroyed (§9.4).
- Policy/issuer admin key compromise → **multisig + timelock + emergency pause** (§4.7).

---

## 3. Cryptographic design

> Primary proving system: **Circom + Groth16** (smallest, cheapest on-chain verify; constant on-chain cost regardless of circuit complexity; matches the official Soroban verifier and the team's Semaphore/Groth16 background). Alternate backends (Noir/UltraHonk, RISC Zero) are supported behind the Verifier Router as stretch (§8).
>
> **`[VERIFY]` curve decision (do this on day 1):** the official `groth16_verifier` example uses **BLS12-381** host functions. Confirm whether to target **BLS12-381** (matches the example) or **BN254** (added in Protocol 25 "X-Ray", expanded in Protocol 26 "Yardstick"). Confirm `snarkjs` can produce proofs for the chosen curve and that the host-function names exist in the installed `soroban-sdk`. Lock the curve before writing the circuit. Use the same curve end-to-end (circom → snarkjs → verifier). Mismatched curve is a silent failure mode.

### 3.1 Credential format
A credential is a set of attribute fields the issuer attests, plus a user secret:
```
credential = {
  user_secret        : field        // user-generated, never leaves device
  issuer_id          : field        // which issuer attested this
  kyc_passed         : bool/field   // 1 = passed
  country            : field        // ISO numeric code
  age                : field        // or birth_year; prove age>=N without revealing
  investor_type      : field        // 0=retail,1=accredited,2=qualified,...
  tx_limit           : field        // per-action limit in atomic units
  issued_at          : field        // epoch
  expires_at         : field        // epoch
}
commitment = Poseidon(user_secret, issuer_id, kyc_passed,
                      country, age, investor_type, tx_limit, issued_at, expires_at)
```
The issuer inserts `commitment` into a Poseidon Merkle tree and publishes the root. The issuer also signs the credential (EdDSA/Poseidon-friendly) so the user can prove issuer attestation in-circuit if desired (stretch; MVP relies on membership under a registered root).

### 3.2 Commitment & Merkle tree
- Poseidon hash (circomlib `poseidon`), fixed arity. Tree depth `D` (e.g. 20 or 32 — choose for capacity; depth does not affect on-chain verify cost, only proving time). **`[VERIFY]`** circomlib Poseidon parameters match any on-chain Poseidon host function if used on-chain.
- Off-chain: issuer maintains the full tree; publishes root. On-chain: store current root per issuer in the Issuer Registry; optionally maintain an on-chain incremental Merkle tree if issuance must be trustless (stretch).

### 3.3 The core circuit (`eligibility.circom`)
**Statement proven (zero-knowledge):** "I hold a credential committed under a registered issuer root, it satisfies the referenced policy, this proof is bound to this exact on-chain action, and I have not used this eligibility before."

```
PUBLIC INPUTS (all enforced by the gate contract against real state/args):
  credential_root      // must equal a root registered for issuer_id
  issuer_id
  policy_id
  // policy parameters (read from Policy Registry by the contract, passed in):
  pol_required_kyc        // 0/1
  pol_required_sanctions  // 0/1
  pol_jurisdiction_root   // Merkle root (or bitmap commitment) of allowed countries
  pol_min_age             // 0 if N/A
  pol_min_investor_type   // 0 if N/A
  // action binding (must equal the actual transaction args):
  action_type             // 0=payment,1=rwa_transfer,...
  asset_id
  amount
  recipient               // hashed Stellar address / contract param
  action_id               // payment_id or asset/allocation id
  packet_hash             // Poseidon hash of the Travel-Rule packet (payment gate)
  // anti-replay / freshness:
  nullifier
  epoch                   // current epoch; proof_expiry checked by contract

PRIVATE INPUTS (witness):
  user_secret, issuer_id, kyc_passed, country, age,
  investor_type, tx_limit, issued_at, expires_at,
  merkle_path[D], merkle_index_bits[D],
  // payment gate only:
  packet_fields...        // originator/beneficiary/amount/corridor/etc.

CONSTRAINTS:
  1. commitment = Poseidon(...all credential fields...)
  2. MerkleVerify(commitment, merkle_path, merkle_index_bits) == credential_root
  3. if pol_required_kyc==1        => kyc_passed==1
  4. sanctions and revocation non-membership verified against committed roots
  5. if pol_min_age>0              => age >= pol_min_age          (range/comparison)
  6. if pol_min_investor_type>0    => investor_type >= pol_min_investor_type
  7. jurisdiction allowed: MerkleVerify(country, country_path, ...) == pol_jurisdiction_root
                           (or set-membership against the allowed-country commitment)
  8. amount <= tx_limit            (range proof; LessEqThan with safe bit-width)
  9. nullifier == Poseidon(user_secret, policy_id, epoch)
 10. packet binding (payment gate): packet_hash == Poseidon(packet_fields...)
 11. action fields are wired as public inputs so the proof is invalid if reused for a
     different (asset_id, amount, recipient, action_id).
```
Notes:
- Keep public-input count modest (on-chain Groth16 cost grows mildly with public inputs). Where possible commit multiple values into one Poseidon hash exposed as a single public input, and have the contract recompute/compare.
- Use audited circom components (circomlib `comparators`, `poseidon`, `smt`/`merkle`). **`[VERIFY]`** exact component names/IO in the installed circomlib version.

### 3.4 Action-binding (the integrity keystone)
The gate contract must, before calling the verifier, assemble the public inputs from the **actual** transaction arguments (asset, amount, recipient, action_id, packet_hash) and the policy it loaded from the registry — then verify the proof against *those*. A proof whose public inputs don't match the real action fails. This is what makes AnchorShield a real gate and not metadata theater. Treat this as the highest-priority correctness property and test it explicitly (a proof minted for action A must fail for action B).

### 3.5 Nullifier scheme
- `nullifier = Poseidon(user_secret, policy_id, epoch)`.
- Stored in the Nullifier Registry on first successful use; second use reverts.
- Scope: per (policy, epoch). Choose epoch semantics per policy: one-time (epoch fixed) vs periodic (epoch = time window) for recurring eligibility (e.g., monthly aid claim). Document the choice per policy.

### 3.6 Revocation & expiry
- **Expiry:** `expires_at` in the credential; the contract checks `epoch <= expires_at` (passed as public input / enforced on-chain).
- **Revocation (stretch but designed-in):** issuer rotates its credential root on revocation (publish new root excluding revoked commitments) — the contract accepts only the current root, so revoked credentials stop verifying. For scale, support an on-chain revocation accumulator or an allow-list epoch root. Document the latency/UX tradeoff.

### 3.7 Selective disclosure / auditor view-keys
- The Travel-Rule packet (and any disclosable attributes) is encrypted to an **auditor public key** (e.g., x25519 + authenticated encryption). On-chain only `packet_hash` is stored.
- An authorized auditor can decrypt the packet off-chain and verify it hashes to the on-chain `packet_hash`, binding the disclosure to the exact payment. This is the "compliant privacy" property SDF funds (view keys / selective disclosure).
- Provide a CLI/dashboard flow for the auditor to request + verify a disclosure.

### 3.8 Sanctions handling (honest scope)
- **Hardened build:** sanctions and revocation status are proven with in-circuit non-membership against committed roots. Demo lists are mock data.
- **Stretch:** in-circuit **non-membership** proof against an on-chain committed `sanctions_root` (which list, which version is committed on-chain). This addresses the "a ZK proof hides the customer, not the list" critique — by committing to the exact list used. Implement with a sorted-Merkle/SMT non-membership gadget.

### 3.9 Trusted setup
Groth16 requires a per-circuit trusted setup. See §9.4 for the ceremony. The circuit must be **frozen** before the phase-2 ceremony; any circuit change invalidates the setup.

---

## 4. On-chain contracts (Soroban, Rust)

> **`[VERIFY]` before writing any contract:** the current `soroban-sdk` version (check crates.io + the official `groth16_verifier` Cargo.toml), the Stellar CLI version and commands (`stellar contract build`, `stellar contract deploy`, `stellar contract invoke`), the exact BLS12-381/BN254 host-function names exposed by the SDK, and the Poseidon host-function availability. Reproduce the official `groth16_verifier` example end-to-end on testnet (verify a trivial `a*b=c` proof) **before** building anything custom. Do not proceed past this gate until a real proof verifies on-chain.

### 4.1 Contract inventory
| Contract | Responsibility |
|---|---|
| `verifier_groth16` | Verify a Groth16 proof against a stored verification key + public inputs. Forked/adapted from the official example. |
| `verifier_router` | Dispatch to a proving-backend verifier by `scheme_id` (groth16 now; ultrahonk/risc0 later). Mirrors Nethermind's router pattern. |
| `issuer_registry` | Register trusted issuers; store each issuer's current `credential_root` + metadata; admin-gated rotation. |
| `policy_registry` | `policy_id → Policy{required_kyc, required_sanctions, jurisdiction_root, min_age, min_investor_type, limit, sanctions_root, expiry_rules, scheme_id, vk_hash}`. Admin-gated CRUD. |
| `nullifier_registry` | Spent-nullifier set; `is_used`, `mark_used` (only callable by gates). |
| `gate_payment` | Travel-Rule/remittance gate: `verify_and_pay(...)`. Loads policy, builds public inputs from real args, verifies, checks+marks nullifier, executes stablecoin transfer, emits event. |
| `gate_rwa` | SEP-57 access gate: `verify_and_transfer(...)`. Same pattern; integrates with a SEP-57/T-REX compliance hook. |

### 4.2 Public input assembly (shared library)
A shared Rust module builds the canonical public-input vector from (policy, action args, nullifier, epoch). Both gates use it. This guarantees action-binding is consistent and is the single place to audit.

### 4.3 `gate_payment` flow (`verify_and_pay`)
```
fn verify_and_pay(env, proof, issuer_id, policy_id, asset, amount, recipient,
                  action_id, packet_hash, nullifier, epoch):
  1. policy = policy_registry.get(policy_id); require active + not expired(epoch)
  2. root   = issuer_registry.current_root(issuer_id); require registered
  3. require epoch within freshness window
  4. require !nullifier_registry.is_used(nullifier)
  5. public_inputs = build_public_inputs(root, issuer_id, policy, action=PAYMENT,
                        asset, amount, recipient, action_id, packet_hash, nullifier, epoch)
  6. require verifier_router.verify(policy.scheme_id, policy.vk_hash, proof, public_inputs)
  7. nullifier_registry.mark_used(nullifier)
  8. token::transfer(asset, from=contract_or_escrow, to=recipient, amount)   // testnet USDC / mock SAC
  9. emit CompliancePaymentApproved{action_id, asset, amount, recipient, packet_hash, nullifier, policy_id}
```
**`[VERIFY]`** the Stellar Asset Contract (SAC) transfer interface and how to move USDC on testnet (issue a test asset or use testnet USDC). Decide escrow vs. direct-authorization model and document it.

### 4.4 `gate_rwa` flow (`verify_and_transfer`)
Same skeleton, `action_type=RWA`, policy enforces jurisdiction + investor_type, and the gate calls into a **SEP-57 / ERC-3643 (T-REX)** compliance/transfer hook. **`[VERIFY]`** the current SEP-57 contract interface on Stellar and the OpenZeppelin Stellar RWA contract API; integrate AnchorShield as the identity/eligibility verifier feeding SEP-57's compliance check (mock the SEP-57 token if a deployable reference isn't available, and say so).

### 4.5 Events
Emit structured events for every approve/reject reason so the indexer and dashboard can render the full compliance trail (without PII). Include `policy_id`, `action_id`, `nullifier`, `packet_hash`, outcome, reason-code.

### 4.6 Storage & cost
- Use appropriate Soroban storage tiers (instance/persistent/temporary) and set TTLs. Nullifiers are persistent. **`[VERIFY]`** current storage API + TTL/rent model.
- Keep public-input count small (cost driver). Benchmark verify cost on testnet; record numbers in `docs/BENCHMARKS.md`.

### 4.7 Admin, upgradeability, safety
- Admin actions (register issuer, set policy, rotate root) gated by a **multisig** with a **timelock** for sensitive changes.
- **Emergency pause / circuit-breaker** per gate (mirror the risc0 verifier's `EmergencyStop` pattern).
- Upgradeable contracts via the standard Soroban upgrade mechanism, gated by the same multisig + timelock. **`[VERIFY]`** current upgrade pattern.

---

## 5. Off-chain components

### 5.1 Issuer Service (`/services/issuer`)
- Verifies a user (mock KYC in MVP; pluggable real KYC provider interface), constructs the credential, inserts the commitment into the Poseidon Merkle tree, signs the credential, and publishes the new root on-chain (via admin/multisig).
- Persists the tree (DB), exposes APIs: `issue_credential`, `get_merkle_path`, `current_root`, `revoke`.
- Issues the encrypted disclosure package (auditor view-key) for the payment flow.

### 5.2 Proof generation (`/packages/prover`)
- **Browser proving** (primary UX: secret never leaves device): compile circuit, ship `wasm` + `zkey`, generate witness + Groth16 proof in-browser via snarkjs. **`[VERIFY]`** snarkjs browser proving works for the chosen curve and circuit size at acceptable time/memory; if too heavy, provide a node-side proving fallback with explicit security note.
- **Node proving** (CI/tests, server option).
- Output: proof + public signals serialized to the exact byte layout the Soroban verifier expects. The serialization/curve step is the #1 place this breaks — write a dedicated converter with golden-vector tests.

### 5.3 Relayer (optional, stretch)
- Allow a user without XLM to submit a proof via a relayer that pays fees (the gate still enforces everything). Bind the proof to the intended recipient/caller to prevent relayer abuse/front-running.

### 5.4 Indexer (`/services/indexer`)
- Subscribe to contract events; build a queryable store of (non-PII) compliance events for the dashboard and analytics. **`[VERIFY]`** current Soroban event-streaming / RPC interface.

---

## 6. SDK & developer experience (`/packages/sdk`)

- **TypeScript SDK**: typed client for all contracts, public-input assembly helpers, proof-gen wrappers, credential management, and a one-call `gate.verifyAndPay(...)` / `gate.verifyAndTransfer(...)`.
- **Contract bindings** generated from the deployed contracts. **`[VERIFY]`** the current `stellar contract bindings typescript` workflow.
- **CLI** (`anchorshield`): scaffold a policy, register an issuer, issue a test credential, generate a proof, run a gate, inspect events.
- **Integration guide**: "Add an AnchorShield gate to your contract in <1 day" — copy-paste recipe + example.
- Publish packages (npm) under a scope once stable. **`[VERIFY]`** naming availability.

---

## 7. Frontend

### 7.1 Demo dApp (`/apps/web`)
- Wallet connect (**`[VERIFY]`** current Stellar wallet kit / Freighter integration).
- **Flow 1 — Remittance:** obtain credential → enter payment (Alice US → Bob NG) → generate proof in-browser → submit → show on-chain verification + success + event + Stellar Expert link. Show "no KYC data on-chain."
- **Flow 2 — RWA:** same credential → buy a mock tokenized treasury → jurisdiction/investor checks → transfer/mint succeeds.
- **Failure theater:** buttons to trigger each rejection (not-eligible, over-limit, wrong jurisdiction, replayed nullifier, packet/action mismatch) and show the contract reverting.

### 7.2 Compliance dashboard (`/apps/dashboard`)
- Auditor view: list compliance events (no PII), request + verify a disclosure via view-key, confirm `packet_hash` binding.

### 7.3 Issuer console (`/apps/issuer-console`)
- Issue/revoke credentials, view current root, manage policies (admin-gated).

> Frontend design: follow the team's existing design standards (distinctive, intentional, accessible — meet WCAG AA contrast; honor `prefers-reduced-motion`; real focus states). Multi-page with a landing page + tabs, not single-page.

---

## 8. Proving-backend strategy (pluggable)

- **M-series core: Circom/Groth16** (primary). Everything above assumes this.
- **Stretch A — Noir/UltraHonk** adapter behind `verifier_router` (`scheme_id=ultrahonk`). Lets you claim "no per-circuit trusted setup." **`[VERIFY]`** current on-chain cost — UltraHonk verification was, pre-Yardstick, near the CPU instruction limit even for simple circuits; measure on a Protocol 26 node before committing. Use `NethermindEth/rs-soroban-ultrahonk`.
- **Stretch B — RISC Zero** adapter for a compliance computation that's awkward as a circuit (e.g., proving a result computed over a structured KYC/credit file). Use `NethermindEth/stellar-risc0-verifier`; mind seal-size + Docker/GPU proving overhead.
- The **Verifier Router** makes these additive: a policy declares its `scheme_id`; gates don't care which backend produced the proof.

---

## 9. Security

### 9.1 Properties to guarantee
Soundness (no valid proof for a false statement), action-binding (no cross-action replay), no double-spend (nullifier), issuer authenticity, revocation/expiry honored, no PII on-chain, admin safety (multisig/timelock/pause).

### 9.2 Anti-front-running
Bind the proof to the submitting caller and/or recipient (include in public inputs), so an observer cannot lift a pending proof from the mempool and redirect funds. Document the chosen binding.

### 9.3 Reviews & tooling
- Internal adversarial review per milestone (dedicated "try to break action-binding / replay / forge" pass).
- Static analysis / linters for Rust + circuits. Circuit-specific checks (e.g., `circomspect`). **`[VERIFY]`** tool availability/versions.
- External/security-reviewer pass before mainnet (use the repo's `security-review` workflow).

### 9.4 Trusted-setup ceremony
- Phase 1: reuse a public Powers-of-Tau of sufficient size for the circuit's constraint count. **`[VERIFY]`** a suitable ptau exists for the chosen curve and size.
- Phase 2: per-circuit contribution. Run a **multi-party** contribution (several independent contributors) for credibility; publish transcript + attestations; **destroy toxic waste**; commit the final `zkey` hash + `vk` and publish verification instructions. Freeze the circuit first.
- Document the entire ceremony in `docs/CEREMONY.md` with reproducible verification.

### 9.5 Key management
- Issuer keys, admin multisig signers, auditor view-keys, deploy keys: documented custody, never in-repo, rotation plan. `.env.example` only.

---

## 10. Testing & CI

### 10.1 Layers
1. **Circuit tests** (`circom_tester`/`snarkjs`): per-constraint positive + negative vectors; golden serialization vectors for the proof→bytes converter.
2. **Contract unit tests** (Soroban Rust test env): every gate path + every revert reason; nullifier reuse; expiry; policy mismatch; action-binding (proof for A rejected for B).
3. **Integration**: issuer → proof → gate → token transfer, in a local/sandbox network. **`[VERIFY]`** `stellar` local network / quickstart (note: may require `--limits unlimited` locally for heavier proofs).
4. **E2E on testnet**: scripted full flow with on-chain verification; assert events; capture tx hashes.
5. **Property/fuzz**: randomized inputs against invariants (no false accept; nullifier monotonic).
6. **Frontend e2e**: the five-failure demo as an automated script.

### 10.2 CI/CD
- CI runs circuit tests, contract tests, integration on a sandbox, lint, and builds the frontends on every PR. Block merge on red. **`[VERIFY]`** runner support for the circom/snarkjs + Rust/Soroban toolchains.
- Pin all toolchain versions (`rust-toolchain.toml`, Node version, circom version, snarkjs version, `soroban-sdk` version) in the repo.

### 10.3 Definition of Done (every task)
Code + tests (incl. a negative test) + passing CI + (for on-chain tasks) a real verification on sandbox or testnet + docs updated. No fabricated APIs. Mocks disclosed.

---

## 11. Deployment & operations

- **Networks:** local sandbox → testnet → mainnet. Flagship payment flow must run on **mainnet** (capture a public tx on Stellar Expert).
- **Deploy scripts** (idempotent), addresses tracked in `deployments/<network>.json`. Never deploy with an unlocked admin key; use the multisig.
- **Monitoring/observability:** indexer health, gate success/reject rates, verify-cost trend, alerting. **`[VERIFY]`** RPC/horizon endpoints.
- **Runbooks:** `docs/RUNBOOK.md` — deploy, rotate issuer root, pause a gate, rotate keys, incident response.
- **Secrets:** environment-injected; documented; rotation plan.

---

## 12. Repository layout (monorepo)

```
anchorshield/
  circuits/                 # eligibility.circom, components, tests, build scripts
  contracts/
    verifier_groth16/
    verifier_router/
    issuer_registry/
    policy_registry/
    nullifier_registry/
    gate_payment/
    gate_rwa/
    shared/                 # public-input assembly lib, types
  packages/
    prover/                 # browser+node proof generation, serialization, golden vectors
    sdk/                    # TS SDK + generated bindings
    cli/                    # anchorshield CLI
  services/
    issuer/                 # issuer service + Merkle tree
    indexer/                # event indexer
    relayer/                # optional
  apps/
    web/                    # demo dApp (remittance + RWA + failure theater)
    dashboard/              # auditor/compliance dashboard
    issuer-console/
  deployments/              # per-network addresses
  docs/                     # this plan, ARCHITECTURE, THREAT-MODEL, CEREMONY, BENCHMARKS, RUNBOOK, API
  scripts/                  # e2e, deploy, demo, ceremony helpers
  .github/workflows/        # CI
```

---

## 13. Milestones (phased; each ends with a working artifact)

> Build in order. Do not start a milestone until the prior milestone's acceptance criteria pass. Deadline-agnostic, but ordered so that even an early stop yields something demonstrable.

**M0 — Toolchain de-risk & spike.** Reproduce the official `groth16_verifier` example end-to-end on testnet (trivial `a*b=c` proof verified on-chain). Lock curve, `soroban-sdk` version, circom/snarkjs versions, CLI commands. Write the proof→bytes converter with golden vectors.
*Accept:* a real proof verifies on-chain on testnet; versions pinned; converter tests green.

**M1 — Core primitive (single policy, single gate).** Credential format + Poseidon Merkle membership circuit + nullifier + action-binding; `verifier_groth16`, `policy_registry`, `nullifier_registry`, `issuer_registry`, `gate_payment`; mock issuer service; node proof-gen.
*Accept:* a valid proof executes a (mock-asset) payment on testnet; the five failure paths revert in contract tests; action-binding test (proof for A rejected for B) passes.

**M2 — Reusability proof (second gate, same credential).** `gate_rwa` integrating a SEP-57/T-REX compliance hook (mock token if needed); policy registry parameterizes both gates; shared public-input lib.
*Accept:* the **same** credential satisfies two different policies through one verifier; both flows verified on testnet.

**M3 — Real UX.** Browser proving; demo dApp (both flows + failure theater); wallet connect; events; Stellar Expert links.
*Accept:* full in-browser demo works on testnet; no PII on-chain; the 5 failures demoable from the UI.

**M4 — Compliance & disclosure.** Auditor view-keys + encrypted Travel-Rule packet + `packet_hash` binding; compliance dashboard; indexer.
*Accept:* auditor can decrypt + verify a disclosure binds to the exact payment; dashboard renders the compliance trail (no PII).

**M5 — Hardening & trust.** Trusted-setup multi-party ceremony; revocation + expiry; admin multisig + timelock + pause; security review; benchmarks; CI complete.
*Accept:* ceremony documented + toxic waste destroyed; revocation works; security review issues resolved; CI green; benchmarks recorded.

**M6 — Mainnet & SDK.** Mainnet deploy of the flagship flow; TS SDK + bindings + CLI; integration guide; published packages.
*Accept:* a public mainnet tx shows a proof verified + action executed; a third-party dev can add a gate using only the SDK + guide.

**Stretch — Backends & advanced ZK.** UltraHonk and/or RISC Zero adapters behind the router; in-circuit sanctions non-membership against an on-chain `sanctions_root`; relayer; recursive/aggregated proofs.
*Accept:* a second proving backend verifies through the router; non-membership sanctions proof verified on-chain.

---

## 14. Codex execution protocol

When building from this plan, Codex MUST:
1. **Start at M0 and respect the gate.** Do not write custom contracts/circuits until a trivial proof verifies on-chain on testnet and all versions are pinned.
2. **Resolve every `[VERIFY]` tag before depending on it.** Check the actual repo/crate/CLI/docs. If a referenced interface differs from this plan, follow the *source*, not the plan, and note the deviation in `docs/DEVIATIONS.md`.
3. **Work in small, tested increments.** One component → tests (incl. a negative test) → green → next. Run the relevant suite after every change and report results.
4. **Never fabricate.** No invented function signatures, host-function names, versions, or APIs. If unknown, stop and surface it.
5. **Keep the README honest.** Mark every mock/stub explicitly. Lead the README with: the secret, the public statement, the circuit, and the contract that verifies it.
6. **Security is a gate, not a phase.** Run the adversarial replay/action-binding/forge checks at the end of M1, M2, and before mainnet.
7. **No secrets committed. No mainnet deploy without the multisig.**
8. **Update docs as you go:** `ARCHITECTURE.md`, `THREAT-MODEL.md`, `BENCHMARKS.md`, `DEVIATIONS.md`, `RUNBOOK.md`.
9. **Definition of Done** per §10.3 for every task.
10. **Branch, don't push to default; never submit anything externally without explicit human approval.**

---

## 15. Open questions / things to confirm before/while building (`[VERIFY]` master list)
1. **Curve:** BLS12-381 (matches official example) vs BN254 (Protocol 25/26). Confirm snarkjs support + host-fn names + pick one end-to-end.
2. **`soroban-sdk` / Stellar CLI versions** and exact verify/host-function APIs (BLS12-381/BN254 ops, Poseidon/Poseidon2).
3. **SEP-57 / T-REX** current Soroban interface + OpenZeppelin Stellar RWA contract API; deployable reference vs mock.
4. **Stablecoin transfer** model on testnet (SAC interface; testnet USDC vs issue a test asset; escrow vs authorization).
5. **Browser proving** feasibility (time/memory) for the real circuit size; fallback plan.
6. **Storage/TTL/rent** model + costs; **event streaming/RPC** for the indexer.
7. **Wallet integration** (Stellar Wallet Kit / Freighter) current API.
8. **circomlib** component names/IO (poseidon, comparators, merkle/smt) in the pinned version.
9. **Powers-of-Tau** availability for the chosen curve/size.
10. **CI runner** support for circom/snarkjs + Rust/Soroban; pin all versions.
11. **Name availability** for npm scope + any trademark check on "AnchorShield."
12. **UltraHonk on-chain cost** on a Protocol 26 node (stretch backend) — measure before committing.

---

## 16. References (verified to exist 2026-06; re-verify exact APIs before use)
- Stellar ZK docs: https://developers.stellar.org/docs/build/apps/zk · Privacy docs: https://developers.stellar.org/docs/build/apps/privacy
- Protocol 25 "X-Ray": https://stellar.org/blog/developers/announcing-stellar-x-ray-protocol-25 · Protocol 26 "Yardstick" (mainnet 2026-05-06): https://stellar.org/blog/foundation-news/yardstick-stellar-protocol-26
- Official Groth16 verifier example: https://github.com/stellar/soroban-examples (→ `groth16_verifier/`)
- UltraHonk verifier: https://github.com/NethermindEth/rs-soroban-ultrahonk
- RISC Zero verifier (router/emergency-stop pattern): https://github.com/NethermindEth/stellar-risc0-verifier
- Stellar private-payments PoC: https://github.com/NethermindEth/stellar-private-payments
- OpenZeppelin Stellar contracts (RWA/SEP-57): https://github.com/OpenZeppelin/stellar-contracts
- SEP-57 / ERC-3643 association: https://stellar.org/press/stellar-development-foundation-joins-erc3643-association · ERC-3643: https://eips.ethereum.org/EIPS/eip-3643
- E2E tutorials: https://jamesbachini.com/circom-on-stellar/ · /noir-on-stellar/ · /stellar-risc-zero-games/
- FATF Recommendation 16 update (June 2025): https://www.fatf-gafi.org/en/publications/Fatfrecommendations/update-Recommendation-16-payment-transparency-june-2025.html

---

*End of Master Build Plan. This is a living document — update `docs/DEVIATIONS.md` whenever reality differs from the plan, and keep this file in sync at milestone boundaries.*
