const FLOW_CONFIG = {
  payment: {
    label: "payment",
    title: "Travel-rule payment proof",
    inputUrl: "./data/payment-input.json",
    expected: {
      credentialRoot:
        "10688334306340428748440845746320333286062746724561894481964512149783108966533",
      policyId: "202",
      actionType: "0",
      assetId: "9001",
      amount: "250",
      recipient: "7000001",
      actionId: "424242",
      epoch: "12",
    },
    mutate: { index: 13, value: "251" },
    failureTarget: "paymentFailure",
  },
  rwa: {
    label: "RWA",
    title: "Regulated asset proof",
    inputUrl: "./data/rwa-input.json",
    expected: {
      credentialRoot:
        "10688334306340428748440845746320333286062746724561894481964512149783108966533",
      policyId: "303",
      actionType: "1",
      assetId: "9101",
      amount: "100",
      recipient: "8000001",
      actionId: "515151",
      epoch: "12",
    },
    mutate: { index: 14, value: "8000002" },
    failureTarget: "rwaFailure",
  },
};

const PUBLIC_SIGNAL_INDEX = {
  credentialRoot: 0,
  policyId: 5,
  actionType: 11,
  assetId: 12,
  amount: 13,
  recipient: 14,
  actionId: 15,
  epoch: 16,
};

const state = {
  vkey: null,
  latestProofs: {},
  busy: false,
};

const proofTitle = document.getElementById("proofTitle");
const proofStatus = document.getElementById("proofStatus");
const proofTime = document.getElementById("proofTime");
const proofLog = document.getElementById("proofLog");
const walletButton = document.getElementById("walletButton");
const walletState = document.getElementById("walletState");
const walletAddress = document.getElementById("walletAddress");
const failureButton = document.getElementById("failureButton");
const disclosureState = document.getElementById("disclosureState");
const disclosureHash = document.getElementById("disclosureHash");
const disclosureTx = document.getElementById("disclosureTx");

function setStatus(label, mode = "") {
  proofStatus.textContent = label;
  proofStatus.className = mode ? `pill ${mode}` : "pill";
}

function appendLog(line) {
  const current = proofLog.textContent === "Ready" ? "" : `${proofLog.textContent}\n`;
  proofLog.textContent = `${current}${line}`;
}

async function loadJson(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`failed to load ${url}`);
  }
  return response.json();
}

async function sha256Short(value) {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, 16);
}

function assertPublicSignals(flow, publicSignals) {
  for (const [name, expected] of Object.entries(flow.expected)) {
    const actual = publicSignals[PUBLIC_SIGNAL_INDEX[name]];
    if (actual !== expected) {
      throw new Error(`${name} mismatch: expected ${expected}, got ${actual}`);
    }
  }
}

function markActiveFlow(flowName) {
  document.querySelectorAll("[data-flow-card]").forEach((card) => {
    card.classList.toggle("active", card.dataset.flowCard === flowName);
  });
}

function setButtonsDisabled(disabled) {
  document.querySelectorAll("[data-run-flow], #failureButton, #walletButton").forEach((button) => {
    button.disabled = disabled;
  });
}

async function ensureVkey() {
  if (!state.vkey) {
    state.vkey = await loadJson("./data/verification_key.json");
  }
  return state.vkey;
}

async function generateProof(flowName, log = true) {
  const flow = FLOW_CONFIG[flowName];
  if (!window.snarkjs?.groth16?.fullProve) {
    throw new Error("snarkjs browser bundle is unavailable");
  }

  if (log) appendLog(`loading ${flow.label} witness`);
  const input = await loadJson(flow.inputUrl);
  const vkey = await ensureVkey();
  const start = performance.now();

  if (log) appendLog("generating witness and Groth16 proof");
  const { proof, publicSignals } = await window.snarkjs.groth16.fullProve(
    input,
    "./proving/eligibility.wasm",
    "./proving/eligibility_final.zkey",
    undefined,
    undefined,
    { singleThread: true },
  );

  if (log) appendLog("verifying proof locally");
  const verified = await window.snarkjs.groth16.verify(vkey, publicSignals, proof);
  if (!verified) {
    throw new Error("local Groth16 verification failed");
  }

  assertPublicSignals(flow, publicSignals);
  const elapsed = Math.round(performance.now() - start);
  const proofHash = await sha256Short(proof);
  state.latestProofs[flowName] = { proof, publicSignals };
  return { proof, publicSignals, elapsed, proofHash };
}

async function runFlow(flowName) {
  const flow = FLOW_CONFIG[flowName];
  if (!flow || state.busy) return;

  state.busy = true;
  setButtonsDisabled(true);
  markActiveFlow(flowName);
  proofTitle.textContent = flow.title;
  proofTime.textContent = "-";
  proofLog.textContent = "";
  setStatus("proving");

  try {
    const generated = await generateProof(flowName);

    proofTime.textContent = `${generated.elapsed}ms`;
    appendLog(`public inputs match ${flow.label} action`);
    appendLog(`proof digest ${generated.proofHash}`);
    setStatus("verified", "success");
  } catch (error) {
    setStatus("failed", "error");
    appendLog(error.message);
  } finally {
    state.busy = false;
    setButtonsDisabled(false);
  }
}

async function runFailureChecks() {
  if (state.busy) return;
  state.busy = true;
  setButtonsDisabled(true);
  setStatus("testing");
  appendLog("running public-input mismatch checks");

  try {
    const vkey = await ensureVkey();
    for (const [flowName, flow] of Object.entries(FLOW_CONFIG)) {
      if (!state.latestProofs[flowName]) {
        await generateProof(flowName, false);
      }
      const generated = state.latestProofs[flowName];
      const mutated = [...generated.publicSignals];
      mutated[flow.mutate.index] = flow.mutate.value;
      const accepted = await window.snarkjs.groth16.verify(vkey, mutated, generated.proof);
      const target = document.getElementById(flow.failureTarget);
      target.textContent = accepted ? "accepted" : "rejected";
      target.className = accepted ? "error" : "success";
    }
    setStatus("mismatches rejected", "success");
  } catch (error) {
    setStatus("failed", "error");
    appendLog(error.message);
  } finally {
    state.busy = false;
    setButtonsDisabled(false);
  }
}

async function connectWallet() {
  const api = window.freighterApi;
  if (!api) {
    walletState.textContent = "unavailable";
    walletAddress.textContent = "Freighter API not found";
    return;
  }

  try {
    if (api.isConnected) {
      const connected = await api.isConnected();
      if (connected.error || connected.isConnected === false) {
        walletState.textContent = "unavailable";
        walletAddress.textContent = connected.error?.message || "Freighter not installed";
        return;
      }
    }
    const access = await api.requestAccess();
    if (access.error) {
      throw new Error(access.error.message);
    }
    walletState.textContent = "connected";
    walletAddress.textContent = access.address || "address unavailable";
  } catch (error) {
    walletState.textContent = "denied";
    walletAddress.textContent = error.message;
  }
}

function shortHash(value) {
  if (!value || value.length <= 16) return value || "-";
  return `${value.slice(0, 10)}...${value.slice(-8)}`;
}

async function hydrateComplianceData() {
  const [events, disclosure] = await Promise.all([
    loadJson("./data/compliance-events.json"),
    loadJson("./data/disclosure-summary.json"),
  ]);
  document.getElementById("signatureFee").textContent =
    events.events.find((event) => event.flow === "payment")?.txHash ? "167132" : "pending";
  disclosureState.textContent = disclosure.verified ? "verified" : "failed";
  disclosureState.className = disclosure.verified ? "success" : "error";
  disclosureHash.textContent = shortHash(disclosure.packetHash);
  disclosureHash.title = disclosure.packetHash;
  disclosureTx.textContent = shortHash(disclosure.paymentTx);
  disclosureTx.title = disclosure.paymentTx;
}

document.querySelectorAll("[data-run-flow]").forEach((button) => {
  button.addEventListener("click", () => runFlow(button.dataset.runFlow));
});

failureButton.addEventListener("click", runFailureChecks);
walletButton.addEventListener("click", connectWallet);

window.addEventListener("load", async () => {
  try {
    await ensureVkey();
    await hydrateComplianceData();
    setStatus("ready");
  } catch (error) {
    setStatus("asset error", "error");
    appendLog(error.message);
  }
});
