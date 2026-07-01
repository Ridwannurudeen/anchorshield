// Live, in-browser KYC via the Sumsub WebSDK. A visitor runs a REAL identity verification; the
// short-lived access token is minted by our backend (/api/kyc/*), never exposing the secret.
// On GREEN, the backend maps the verified document to the credential fields the circuit uses.
(function () {
  const SDK_SRC =
    "https://static.sumsub.com/idensic/static/sns-websdk-builder.js";
  let userId = null;
  let statusToken = null;
  let pollTimer = null;
  let pollFailures = 0;

  function set(id, text, cls) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = text;
    if (cls) el.className = cls;
  }

  function loadSdk() {
    return new Promise((resolve, reject) => {
      if (window.snsWebSdk) return resolve();
      const s = document.createElement("script");
      s.src = SDK_SRC;
      s.onload = () => resolve();
      s.onerror = () => reject(new Error("failed to load Sumsub WebSDK"));
      document.head.appendChild(s);
    });
  }

  async function mintToken(existingUserId) {
    const body =
      existingUserId && statusToken
        ? { userId: existingUserId, statusToken }
        : {};
    const res = await fetch("/api/kyc/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`token endpoint HTTP ${res.status}`);
    return res.json();
  }

  async function pollStatus() {
    try {
      const res = await fetch("/api/kyc/status", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ statusToken }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || `status endpoint HTTP ${res.status}`);
      }
      pollFailures = 0;
      const answer = data.reviewAnswer;
      set(
        "kycStatus",
        answer ? `review: ${answer}` : "verification in progress...",
        answer === "GREEN" ? "success" : answer === "RED" ? "error" : "pending",
      );
      if (answer === "GREEN" && data.credential && !data.credential.error) {
        const c = data.credential;
        set(
          "kycCredential",
          `kyc_passed=${c.kyc_passed} | country=${c.country} | age=${c.age}`,
          "success",
        );
        clearInterval(pollTimer);
      }
      if (answer === "RED") {
        // Final reject: stop the interval. A retry inside the widget still
        // re-polls via the onApplicantStatusChanged event handler.
        clearInterval(pollTimer);
      }
    } catch (e) {
      // Transient failures keep polling, but a persistently failing status
      // endpoint must surface instead of being swallowed forever.
      pollFailures += 1;
      if (pollFailures >= 12) {
        clearInterval(pollTimer);
        set("kycStatus", `status polling stopped: ${e.message}`, "error");
      }
    }
  }

  async function start() {
    const btn = document.getElementById("startKyc");
    btn.disabled = true;
    set("kycStatus", "minting access token...", "pending");
    try {
      const tok = await mintToken();
      userId = tok.userId;
      statusToken = tok.statusToken;
      if (!statusToken) throw new Error("status token missing");
      set("kycStatus", "launching verification widget...", "pending");
      await loadSdk();
      const sdk = window.snsWebSdk
        .init(tok.token, async () => {
          const refreshed = await mintToken(userId);
          statusToken = refreshed.statusToken;
          return refreshed.token;
        })
        .withConf({ lang: "en" })
        .withOptions({ addViewportTag: false, adaptIframeHeight: true })
        .on("idCheck.onApplicantStatusChanged", () => pollStatus())
        .on("idCheck.onError", (e) =>
          set(
            "kycStatus",
            `widget error: ${e?.error || JSON.stringify(e)}`,
            "error",
          ),
        )
        .build();
      sdk.launch("#sumsub-websdk");
      set("kycStatus", "complete the steps in the widget...", "pending");
      pollTimer = setInterval(pollStatus, 5000);
    } catch (e) {
      set("kycStatus", `error: ${e.message}`, "error");
      btn.disabled = false;
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    const btn = document.getElementById("startKyc");
    if (btn) btn.addEventListener("click", start);
  });
})();
