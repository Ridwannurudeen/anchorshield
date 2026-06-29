// Live, in-browser RWA eligibility proof. Anyone can generate and verify the regulated-asset
// Groth16 proof client-side — the exact proof identity_verifier.attest_for_mint checks on-chain.
// This is the permissionless proving step; the on-chain mint itself is gated to the registered
// minter (account == RwaRecipient, require_auth), so that part stays a permissioned action.
(function () {
  const INPUT_URL = "./data/rwa-input.json";
  const VKEY_URL = "./data/verification_key.json";
  const WASM_URL = "./proving/eligibility.wasm";
  const ZKEY_URL = "./proving/eligibility_final.zkey";
  const IDX = {
    termsHash: 1,
    assetId: 12,
    amount: 13,
    recipient: 14,
    actionId: 15,
  };
  let vkey = null;

  function set(id, text, cls) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = text;
    if (cls) el.className = cls;
  }

  function log(msg) {
    const el = document.getElementById("rwaProofLog");
    if (el)
      el.textContent += `${el.textContent && el.textContent !== "Ready" ? "\n" : ""}${msg}`;
  }

  async function digestShort(value) {
    const data = new TextEncoder().encode(JSON.stringify(value));
    const hash = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(hash))
      .slice(0, 6)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  async function run() {
    const btn = document.getElementById("runRwaProof");
    btn.disabled = true;
    set("rwaProofStatus", "proving", "pending");
    const logEl = document.getElementById("rwaProofLog");
    if (logEl) logEl.textContent = "";
    try {
      if (!window.snarkjs?.groth16?.fullProve) {
        throw new Error("snarkjs browser bundle is unavailable");
      }
      log("loading regulated-asset witness");
      const input = await fetch(INPUT_URL).then((r) => r.json());
      if (!vkey) vkey = await fetch(VKEY_URL).then((r) => r.json());
      const start = performance.now();
      log("generating witness and Groth16 proof");
      const { proof, publicSignals } = await window.snarkjs.groth16.fullProve(
        input,
        WASM_URL,
        ZKEY_URL,
        undefined,
        undefined,
        { singleThread: true },
      );
      log("verifying proof locally");
      const ok = await window.snarkjs.groth16.verify(
        vkey,
        publicSignals,
        proof,
      );
      if (!ok) throw new Error("local Groth16 verification failed");
      const elapsed = Math.round(performance.now() - start);
      set("rwaProofAsset", publicSignals[IDX.assetId]);
      set("rwaProofAmount", publicSignals[IDX.amount]);
      set("rwaProofRecipient", publicSignals[IDX.recipient]);
      set("rwaProofAction", publicSignals[IDX.actionId]);
      const terms = publicSignals[IDX.termsHash];
      set("rwaProofTerms", `${terms.slice(0, 10)}…${terms.slice(-6)}`);
      log(`proof digest ${await digestShort(proof)}`);
      log(
        `verified in ${elapsed}ms — the exact proof attest_for_mint verifies on-chain`,
      );
      set("rwaProofStatus", "verified", "success");
    } catch (e) {
      set("rwaProofStatus", "failed", "error");
      log(e.message);
    } finally {
      btn.disabled = false;
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    const btn = document.getElementById("runRwaProof");
    if (btn) btn.addEventListener("click", run);
  });
})();
