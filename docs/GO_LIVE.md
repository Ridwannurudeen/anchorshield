# Go-Live Guides — Closing the Remaining Bucket B Gates

Each remaining `npm run bucket-b:preflight` gate is closed by a **real artifact produced with a
real external party**. This doc maps every gate to: what the preflight literally checks, who
supplies the input, the exact steps, and the verify command. Re-run `node scripts/bucket-b-preflight.mjs`
after each — it turns green only when the genuine artifact exists.

> Honesty rule baked into the gates: each one demands the _independent/external/licensed_ version.
> Do not place a self-produced stand-in at these paths — that defeats the gate's purpose.

---

## B2 — Real anchor (licensed/configured partner)

**Preflight checks (`scripts/bucket-b-preflight.mjs:62-73`):**

- `services/anchor/anchor.config.json` exists, AND
- `services/anchor/out/sandbox-run.json` has `schema:"anchorshield.anchor_sandbox_run.v1"`,
  `mode:"real-anchor-sandbox"`, and non-empty `price`, `quote`, **and `transaction`**.

`services/anchor/sep-client.js` (`runSandboxFlow`) already emits exactly that shape. testanchor only
failed at the final `transaction` (its sandbox doesn't define SEP-31 asset `fields`). A partner anchor
that has the asset configured completes it.

**Who:** your anchor partner (sandbox endpoints + credentials + a configured receive asset).

**Steps**

1. Get from the partner: their SEP-1 `stellar.toml` (`WEB_AUTH_ENDPOINT`, `DIRECT_PAYMENT_SERVER`
   = SEP-31, `ANCHOR_QUOTE_SERVER` = SEP-38, `KYC_SERVER` = SEP-12), the receive **asset code** +
   SEP-38 asset string, the supported **`funding_method`**, and the SEP-12 **customer types/fields**.
2. Bootstrap the per-run credentials (ephemeral — never commit). The pattern is in
   `services/anchor/run-testanchor.mjs`:
   - **SEP-10:** `GET {webAuthEndpoint}?account=<G_ADDR>&home_domain=<domain>`, sign the returned
     challenge with your Stellar key, `POST {webAuthEndpoint}` with the signed XDR → keep `token`.
   - **SEP-12:** with that bearer token, `PUT {KYC_SERVER}/customer` for the sender and receiver
     types the partner requires → keep each `id`.
3. Copy `services/anchor/anchor.config.example.json` → `services/anchor/anchor.config.json` and fill:
   `homeDomain`, `webAuthEndpoint`, `transferServerSep31`, `anchorQuoteServer`, `token`, `sellAsset`,
   `buyAsset`, `receiveAssetCode`, `fundingMethod`, `senderId`, `receiverId`, a future
   `quoteExpiresAt` (ISO), and `packetHash`/`actionBinding` (public signals 1 and 3 from a generated
   proof's `public.json`).
4. Run from a host with network to the partner (WSL on this box): `node services/anchor/sep-client.js`
   → writes `services/anchor/out/sandbox-run.json` with `price`, `quote`, and the receive `transaction`.
5. **Verify:** `node scripts/bucket-b-preflight.mjs` → `ok - B2 real anchor sandbox evidence`.

Background: `docs/ANCHOR_SANDBOX.md`.

---

## B3 — Production trusted-setup ceremony

**Preflight checks (`:74-79`):** `ceremony/production/transcript.json` exists.

**Who:** you + **independent external contributors** + a **future public randomness beacon**.

The current `scripts/ceremony.sh` is autonomous-tier (one operator). Production requires
(`docs/CEREMONY.md` §Production Requirement):

**Steps**

1. Freeze `circuits/eligibility.circom` + `circuits/components/*` (no further circuit edits).
2. **Phase 1 (powers of tau)** and **Phase 2 (Groth16 zkey)** with **each contribution performed by a
   different independent party on their own machine**: pass the `.ptau`/`.zkey` between contributors;
   each runs `snarkjs powersoftau contribute` / `snarkjs zkey contribute` with their **own** fresh
   entropy and discards their toxic waste.
3. **Final beacon = a future public randomness value** (e.g. a specific `drand` round at a
   pre-announced time) — never operator-chosen.
4. `snarkjs zkey verify` the final key. Record into `ceremony/production/transcript.json`: each
   contributor (name/affiliation), per-contribution hashes, the beacon (drand round + value), the
   final zkey hash, and the verification result.
5. Replace `apps/web/proving/eligibility_final.zkey` + the verification key with the ceremony output,
   and **re-freeze the verifier VK on-chain** (`verifier.freeze_vk`).
6. **Verify:** `node scripts/bucket-b-preflight.mjs` → `ok - B3 production ceremony transcript`.

---

## B3 — External security audit

**Preflight checks (`:80-87`):** `audits/external-security-review.md` **or** `.pdf` exists.

**Who:** an **independent third-party** auditor (not the builder — that's why a self-review can't go here).

**Steps**

1. Engage an external firm/reviewer. Scope: `contracts/` (Soroban), `circuits/eligibility.circom`,
   and the issuer/anchor services. Give them the repo + `docs/THREAT_MODEL.md` +
   `docs/SECURITY_REVIEW.md` (the self-review, as background).
2. Commit their report at `audits/external-security-review.md` (or `.pdf`).
3. Triage; resolve all Critical/High before mainnet.
4. **Verify:** `node scripts/bucket-b-preflight.mjs` → `ok - B3 external audit report`.

---

## B3 — Mainnet governance config (multisig + timelock)

**Preflight checks (`:88-93`):** `deployments/admin-governance.mainnet.json` exists.

**Who:** you + your **real independent signers** (distinct people/entities, hardware/org keys).

> Do this ONLY with genuinely independent signers. A single party holding all keys in a "3-of-5" is
> single custody pretending to be a multisig — strictly worse than the honest single admin.

**Steps**

1. Collect the real public keys of the independent signers.
2. Deploy `contracts/governance` to **mainnet**; `init` with the signer set + thresholds + delays
   (template values in `deployments/admin-governance.mainnet.example.json`: 3-of-5, ~24h normal /
   ~1h emergency).
3. Copy the example → `deployments/admin-governance.mainnet.json` and fill `governance_contract`
   (the mainnet deploy), `source` (mainnet deployer), the real `signers`, and the mainnet
   `governed_contracts` IDs.
4. Migrate admin with the two-step handoff: call `transfer_admin(<governance_contract_id>)` on all
   eight governed contracts, verify `pending_admin`, then execute governance
   `AcceptAdmin(<contract_id>)` for each contract (`docs/MAINNET_RUNBOOK.md` step 5).
5. **Verify:** `node scripts/bucket-b-preflight.mjs` → `ok - B3 mainnet governance config`.

---

## B3 — Mainnet approval marker

**Preflight checks (`:94-100`):** `ANCHORSHIELD_MAINNET_APPROVED=1` in the environment.

**Who:** you — the final go/no-go, only after everything above is **real and complete**.

**Steps**

1. Confirm: production ceremony done, external audit's Crit/High resolved, governance migrated to a
   real multisig, and real anchor evidence captured.
2. `ANCHORSHIELD_MAINNET_APPROVED=1 npm run mainnet:preflight` (it cross-checks the other gates).
3. Then follow `docs/MAINNET_RUNBOOK.md` for the staged deploy.

---

## Verify the whole bucket

```bash
node scripts/bucket-b-preflight.mjs   # all green once every real artifact exists
```

Order to execute with partners: **external audit** and **production ceremony** in parallel (longest
lead time) → **anchor partner evidence** → **governance config + admin migration** → finally the
**mainnet approval marker**. The npm publish (B4) is already done.
