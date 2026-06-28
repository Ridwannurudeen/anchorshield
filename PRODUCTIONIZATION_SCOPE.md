# Productionization Scope — Tracks 1 & 2 (KYC Issuer + Real OFAC Sanctions)

Handover for Codex. Goal: replace the two mock data sources (credentials, sanctions/
revocation lists) with a real off-chain **issuer service** that produces roots and
witnesses **compatible with the already-deployed circuit** — no circuit recompile.

Tracks 3 (real anchor) and 4 (mainnet/audit/ceremony) stay out of scope (see
`docs/ROADMAP.md`). Nothing is committed/pushed/submitted without explicit user approval.

---

## 0. Already done by Claude (verified — build ON this, do not redo)

- **`services/issuer/lib/zk-tree.js`** — shared crypto/tree core. Reuses the proven
  Poseidon255 from `scripts/m1-circuit-smoke.js` and reads the SAME constants file
  (`circuits/components/poseidon255_constants.circom`) so it cannot drift from the circuit.
  Exports: `poseidon255, foldHash, low248Hash, merkleRoot, credentialHash, sanctionsKey,
  revocationKey, buildTree(leaves, depth), buildExclusionTree(values, depth), decimal,
  FIELD_PRIME`.
  - `buildTree` = fixed-depth LeanIMT (empty node = 0; internal = `Poseidon255(left,right)`;
    pair order by index bit). Returns `{ root, siblings(index), levels }`.
  - `buildExclusionTree` = indexed Merkle tree, sorted `(value, next)` linked list, leaves
    `Poseidon255(value, next)`. Returns `{ root, nodes, isMember(key), witnessFor(key) }`.
    `witnessFor` throws for a member (this is exactly how a sanctioned key is blocked).
- **`services/issuer/test.js`** — parity gate, 6/6 green via `node services/issuer/test.js`.
  Proves the module reproduces the DEPLOYED fixtures: empty exclusion root
  `41464577938942170799849979391610616316800580958977068940122632529344071768263`
  and single-credential root
  `5634016141864094715384210201492604405167036651107015292298066213267081614816`.
- **`docs/ROADMAP.md`** — all four productionization tracks documented.

Run `node services/issuer/test.js` first to confirm the core still passes before extending.

---

## 1. Hard invariants (verified against source — get any of these wrong and roots won't verify)

- **Hash**: custom `Poseidon255` over BLS12-381 scalar field. `circomlib` (BN254) is NOT
  compatible. Constants are scraped from `circuits/components/poseidon255_constants.circom`
  at runtime — reuse `zk-tree.js`, do not reimplement.
- **Credential leaf** (`circuits/eligibility.circom:249-258`) = `FoldHash(9)` (a *chain* of
  2-input Poseidons, not a 9-arity hash) over, in this exact order:
  `[user_secret, issuer_id, kyc_passed, country, age, investor_type, tx_limit, issued_at, expires_at]`.
- **Credential tree**: `MerkleProof(treeDepth)`, **depth = 2** (`eligibility.circom:331`,
  `Eligibility(2,20,20)`) → **max 4 credentials**. Node order is index-bit, not sorted.
- **Sanctions key** = `Low248(user_secret, issuer_id)` (`eligibility.circom:266-268`).
- **Revocation key** = `Low248(credentialHash)` (`eligibility.circom:278-279`).
- **Exclusion trees**: indexed Merkle tree, **depth 20**, leaf = `Poseidon255(low_value, low_next)`,
  keys range-checked to 248 bits, `low_next == 0` = end-of-list sentinel. Non-membership =
  `low_value < key < low_next` (or `low_next == 0`).
- **Public signal layout (PUBLIC_SIGNAL_COUNT = 19)**: `[0]` credential_root (output),
  `[1]` packet_hash, `[2]` nullifier, `[3]` action_binding, `[4]` issuer_id … `[16]` epoch,
  `[17]` sanctions_root, `[18]` revocation_root. Index map in
  `scripts/m1-circuit-smoke.js:25-41`.
- **On-chain root setting** (`scripts/deploy-testnet.sh:113-116,142-144`): roots passed as
  **bare decimal `Bls12381Fr`** on the CLI —
  `set_root --issuer_id 101 --root <dec>`, `set_sanctions_root --root <dec>`,
  `set_revocation_root --issuer_id 101 --root <dec>`. Contract sigs in
  `contracts/issuer_registry/src/lib.rs:60,78,92`.
- **Key bridge (design)**: the sanctions tree is keyed by the USER's secret, so OFAC names are
  NOT hashed in directly. The issuer screens its roster against OFAC and inserts the
  *matched users'* sanctions keys. So #1 (issue/roster) and #2 (screen) are one service.

---

## 2. Track 1 — KYC issuer service

Build `services/issuer/issue.js` (+ `data/roster.json`):
1. Input: a roster of users with credential fields (synthetic for demo; design a thin
   adapter seam for a real KYC sandbox API as a follow-up). Demo roster ≤ 4 users (depth-2
   limit). Each user has a `user_secret` and the 9 credential fields.
2. For each user: `credentialHash(user)` → leaf. `buildTree(leaves, 2)` → credential root +
   per-user `{ merkle_index, merkle_siblings }`.
3. Emit `services/issuer/out/issuance.json`: credential root (decimal), and per-user record
   (fields + witness) for the prover.
4. Wire the root into the existing `set_root --issuer_id 101 --root <root>` call (reuse the
   `inv` helper / deploy script pattern; do not invent a new invoke path).

## 3. Track 2 — real OFAC sanctions + revocation

Build `services/issuer/lib/ofac.js`, `services/issuer/ofac-sync.js`, extend `issue.js`:
1. **Parser** for OFAC legacy **SDN.CSV** (12 cols, no header, `-0-` = empty):
   `ent_num, SDN_Name, SDN_Type, Program, Title, Call_Sign, Vess_type, Tonnage, GRT,
   Vess_flag, Vess_owner, Remarks`. (Verify column order against the live file / OFAC spec
   FAQ topic 1641 at build time.) Normalize names (uppercase, strip punctuation, collapse
   whitespace). Optionally also parse `alt.csv` for aka aliases.
2. **`ofac:sync`** npm script → fetch `https://www.treasury.gov/ofac/downloads/sdn.csv`
   (≈10 MB; the sandbox here cannot reach treasury.gov, but Codex's build env / the user
   can) into `services/issuer/data/sdn.csv`. Also commit a **small real sample**
   (`data/sample-sdn.csv`) — extract a handful of genuine rows from the freshly-synced file;
   do NOT fabricate entries.
3. **Screen** the roster against the parsed list (normalized name match). For each matched
   user → `sanctionsKey(user)`. `buildExclusionTree(matchedKeys, 20)` → sanctions root +
   `witnessFor(cleanUserKey)` for each non-matched user.
4. **Revocation**: maintain a revoked-credential set; `revocationKey(user)` for revoked
   users; `buildExclusionTree(revokedKeys, 20)` → revocation root + witnesses.
5. Wire roots into `set_sanctions_root --root <root>` and
   `set_revocation_root --issuer_id 101 --root <root>`.

## 4. END-TO-END VALIDATION GATE (this is the proof it actually works)

Using the EXISTING deployed artifacts (`apps/web/proving/eligibility.wasm` +
`eligibility_final.zkey`; no recompile):
1. Build a FULL witness for a **clean** roster user against the POPULATED credential +
   sanctions + revocation trees (credential witness from `buildTree`; exclusion witnesses
   from `buildExclusionTree.witnessFor`). Patch into the witness shape used by
   `scripts/m1-circuit-smoke.js` / `scripts/build-proof-pool.mjs`.
2. `snarkjs.groth16.fullProve` → `groth16.verify` against the deployed VK → MUST verify.
   (snarkjs is pure JS/wasm — runs fine on Windows, no linker/SAC issue.)
3. Build a witness for an **OFAC-matched** user → `witnessFor` throws / proof fails. Show
   both outcomes in the test output.
4. Add `services/issuer/test.js` cases for: parser correctness, screening hit/miss,
   populated-tree witness verifies via `merkleRoot`, member refusal.

## 5. Out of scope / notes

- **No circuit recompile.** Scaling past 4 credentials needs deeper `treeDepth` → new
  zkey/VK + re-freeze + new ceremony; that's a Track-4 roadmap item, not this work.
- Cargo/contract work runs in **WSL** (`bash scripts/test.sh`); Windows host has no MSVC
  linker + Smart App Control blocks fresh test exes. Node/snarkjs run on Windows.
- Gotcha: the security hook blocks any `0x`+64-hex literal (looks like a private key) — write
  the BLS field prime in decimal (see `zk-tree.js`). A formatter reformats files on write.
- Keep `set_*` root args as bare decimal field elements < r.
```
Quickstart for Codex:
  node services/issuer/test.js          # confirm core parity (6/6)
  npm run ofac:sync                     # fetch live SDN.csv (needs open network)
  node services/issuer/issue.js         # build roots + witnesses
  # then the end-to-end fullProve/verify gate in §4
```
