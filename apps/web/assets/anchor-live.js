// Live, in-browser anchor flow against the SDF public reference anchor (testanchor.stellar.org).
// Anyone with Freighter can run a REAL SEP-10 authentication + SEP-38 quote, signed by their own
// wallet, in real time — nothing pre-recorded. testanchor allows CORS, so no backend is needed.
// SEP-31 receive-create needs a configured/licensed anchor (testanchor's sandbox lacks asset fields).
(function () {
  const BASE = "https://testanchor.stellar.org";
  const HOME = "testanchor.stellar.org";
  const BUY_ASSET =
    "stellar:SRT:GCDNJUBQSX7AJWLJACMJ7I4BC3Z47BQUTMHEICZLE6MU4KQBRYG5JY6B";

  function set(id, text, cls) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = text;
    if (cls) el.className = cls;
  }

  async function call(url, opts) {
    const res = await fetch(url, opts);
    const text = await res.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
    if (!res.ok) {
      const msg =
        data && typeof data === "object"
          ? data.error || JSON.stringify(data)
          : String(data).slice(0, 140);
      throw new Error(`HTTP ${res.status} ${msg}`);
    }
    return data;
  }

  async function run() {
    const btn = document.getElementById("runLiveAnchor");
    btn.disabled = true;
    set("liveAnchorAuth", "running", "pending");
    set("liveAnchorQuote", "running", "pending");
    try {
      const api = window.freighterApi;
      if (!api?.signTransaction) {
        throw new Error(
          "Freighter not found — install the Freighter extension",
        );
      }
      set("liveAnchorStatus", "connecting wallet…", "pending");
      if (api.requestAccess) await api.requestAccess();
      const account = (await api.getAddress()).address;
      set("liveAnchorAccount", `${account.slice(0, 6)}…${account.slice(-4)}`);

      set(
        "liveAnchorStatus",
        "SEP-10: fetching challenge from testanchor…",
        "pending",
      );
      const challenge = await call(
        `${BASE}/auth?account=${account}&home_domain=${HOME}`,
      );
      set(
        "liveAnchorStatus",
        "SEP-10: sign the challenge in Freighter…",
        "pending",
      );
      const signed = await api.signTransaction(challenge.transaction, {
        networkPassphrase: challenge.network_passphrase,
        address: account,
      });
      const xdr = signed.signedTxXdr || signed;
      const token = (
        await call(`${BASE}/auth`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ transaction: xdr }),
        })
      ).token;
      set("liveAnchorAuth", "authenticated", "success");

      set("liveAnchorStatus", "SEP-38: requesting a real quote…", "pending");
      const price = await call(
        `${BASE}/sep38/price?context=sep31&sell_asset=iso4217:USD&buy_asset=${encodeURIComponent(BUY_ASSET)}&sell_amount=250`,
        { headers: { Authorization: `Bearer ${token}` } },
      );
      set(
        "liveAnchorQuote",
        price.price
          ? `250 USD → ${price.total_price || price.price} SRT`
          : "quote received",
        "success",
      );
      set(
        "liveAnchorStatus",
        "Done — real SEP-10 auth + SEP-38 quote, signed by your wallet against testanchor.",
        "success",
      );
    } catch (error) {
      set("liveAnchorStatus", `error: ${error.message}`, "error");
      set("liveAnchorAuth", "not run", "pending");
      set("liveAnchorQuote", "not run", "pending");
    } finally {
      btn.disabled = false;
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    const btn = document.getElementById("runLiveAnchor");
    if (btn) btn.addEventListener("click", run);
  });
})();
