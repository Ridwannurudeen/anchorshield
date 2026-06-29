const FLOW_CONFIG = {
  payment: {
    label: "payment",
    title: "Travel-rule payment proof",
    inputUrl: "./data/payment-input.json",
    expected: {
      credentialRoot:
        "45037060442104923571062605318803772865220986947515516796961646805419810396899",
      policyId: "202",
      actionType: "0",
      assetId: "9001",
      amount: "250",
      recipient: "7000001",
      actionId: "424242",
      epoch: "12",
      sanctionsRoot:
        "28244391006650305950885317775462315324257726777689173131376288148674963252046",
      revocationRoot:
        "16121972906969319149086174845384184675905388596140385334169034751742031498531",
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
        "45037060442104923571062605318803772865220986947515516796961646805419810396899",
      policyId: "303",
      actionType: "1",
      assetId: "9101",
      amount: "100",
      recipient: "8000001",
      actionId: "515151",
      epoch: "12",
      sanctionsRoot:
        "28244391006650305950885317775462315324257726777689173131376288148674963252046",
      revocationRoot:
        "16121972906969319149086174845384184675905388596140385334169034751742031498531",
    },
    mutate: { index: 14, value: "8000002" },
    failureTarget: "rwaFailure",
  },
};

const PUBLIC_SIGNAL_INDEX = {
  credentialRoot: 0,
  packetHash: 1,
  nullifier: 2,
  actionBinding: 3,
  policyId: 5,
  actionType: 11,
  assetId: 12,
  amount: 13,
  recipient: 14,
  actionId: 15,
  epoch: 16,
  sanctionsRoot: 17,
  revocationRoot: 18,
};

const TESTNET_RPC_URL = "https://soroban-testnet.stellar.org";
const USED_PAYMENT_EPOCHS_KEY = "anchorshield.usedPaymentEpochs";

const state = {
  vkey: null,
  deployments: null,
  gatePaymentSpec: null,
  latestProofs: {},
  mockAnchor: null,
  proofPool: null,
  disclosureVault: null,
  walletAddress: "",
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
const submitPaymentButton = document.getElementById("submitPaymentButton");
const submitEpoch = document.getElementById("submitEpoch");
const submitTx = document.getElementById("submitTx");
const submitReplay = document.getElementById("submitReplay");
const disclosureState = document.getElementById("disclosureState");
const disclosureHash = document.getElementById("disclosureHash");
const disclosureTx = document.getElementById("disclosureTx");

function setStatus(label, mode = "") {
  if (!proofStatus) return;
  proofStatus.textContent = label;
  proofStatus.className = mode ? `pill ${mode}` : "pill";
}

function appendLog(line) {
  if (!proofLog) return;
  const current =
    proofLog.textContent === "Ready" ? "" : `${proofLog.textContent}\n`;
  proofLog.textContent = `${current}${line}`;
}

async function loadJson(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`failed to load ${url}`);
  }
  return response.json();
}

function normalizeSignals(publicSignals) {
  return publicSignals.map((signal) =>
    signal && typeof signal === "object" && "u256" in signal
      ? signal.u256
      : String(signal),
  );
}

async function sha256Short(value) {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, 16);
}

function assertPublicSignals(flow, publicSignals, expected = flow.expected) {
  for (const [name, expectedValue] of Object.entries(expected)) {
    const actual = publicSignals[PUBLIC_SIGNAL_INDEX[name]];
    if (actual !== expectedValue) {
      throw new Error(
        `${name} mismatch: expected ${expectedValue}, got ${actual}`,
      );
    }
  }
}

function usedPaymentEpochs() {
  try {
    return new Set(
      JSON.parse(localStorage.getItem(USED_PAYMENT_EPOCHS_KEY) || "[]"),
    );
  } catch {
    return new Set();
  }
}

function markPaymentEpochUsed(epoch) {
  const used = usedPaymentEpochs();
  used.add(Number(epoch));
  localStorage.setItem(
    USED_PAYMENT_EPOCHS_KEY,
    JSON.stringify([...used].sort((a, b) => a - b)),
  );
}

async function ensureProofPool() {
  if (!state.proofPool) {
    const pool = await loadJson("./data/payment-proof-pool.json");
    state.proofPool = pool.entries;
  }
  return state.proofPool;
}

async function ensureDeployments() {
  if (!state.deployments) {
    state.deployments = await loadJson("./data/deployments.json");
  }
  return state.deployments;
}

async function ensureGatePaymentSpec() {
  if (!state.gatePaymentSpec) {
    const spec = await loadJson("./data/gate-payment-spec.json");
    state.gatePaymentSpec = spec.entries;
  }
  return state.gatePaymentSpec;
}

async function ensureMockAnchor() {
  if (!state.mockAnchor) {
    state.mockAnchor = await loadJson("./data/mock-anchor.json");
  }
  return state.mockAnchor;
}

async function ensureDisclosureVault() {
  if (!state.disclosureVault) {
    state.disclosureVault = await loadJson("./data/disclosure-vault.json");
  }
  return state.disclosureVault;
}

async function paymentPoolEntry() {
  const pool = await ensureProofPool();
  const used = usedPaymentEpochs();
  return pool.find((entry) => !used.has(entry.epoch)) || pool[0];
}

function markActiveFlow(flowName) {
  document.querySelectorAll("[data-flow-card]").forEach((card) => {
    card.classList.toggle("active", card.dataset.flowCard === flowName);
  });
}

function setButtonsDisabled(disabled) {
  document
    .querySelectorAll(
      "[data-run-flow], #failureButton, #walletButton, #submitPaymentButton",
    )
    .forEach((button) => {
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
  let expected = flow.expected;
  let poolEntry = null;
  if (flowName === "payment") {
    poolEntry = await paymentPoolEntry();
    input.epoch = String(poolEntry.epoch);
    expected = { ...flow.expected, epoch: String(poolEntry.epoch) };
    if (submitEpoch) submitEpoch.textContent = String(poolEntry.epoch);
  }
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
  const verified = await window.snarkjs.groth16.verify(
    vkey,
    publicSignals,
    proof,
  );
  if (!verified) {
    throw new Error("local Groth16 verification failed");
  }

  assertPublicSignals(flow, publicSignals, expected);
  if (poolEntry) {
    const poolSignals = normalizeSignals(poolEntry.pub_signals);
    const generatedSignals = normalizeSignals(publicSignals);
    if (JSON.stringify(poolSignals) !== JSON.stringify(generatedSignals)) {
      throw new Error(
        "converted payment proof does not match generated public signals",
      );
    }
  }
  const elapsed = Math.round(performance.now() - start);
  const proofHash = await sha256Short(proof);
  state.latestProofs[flowName] = { proof, publicSignals, poolEntry, input };
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
      const accepted = await window.snarkjs.groth16.verify(
        vkey,
        mutated,
        generated.proof,
      );
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
        walletAddress.textContent =
          connected.error?.message || "Freighter not installed";
        return;
      }
    }
    const access = await api.requestAccess();
    if (access.error) {
      throw new Error(access.error.message);
    }
    walletState.textContent = "connected";
    state.walletAddress = access.address || "";
    walletAddress.textContent = state.walletAddress || "address unavailable";
    return state.walletAddress;
  } catch (error) {
    walletState.textContent = "denied";
    walletAddress.textContent = error.message;
    throw error;
  }
}

function hexToBytes(hex) {
  if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length % 2 !== 0) {
    throw new Error("invalid proof hex");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function paymentArgs(StellarSdk, specEntries, proofAbc, signals) {
  const spec = new StellarSdk.contract.Spec(specEntries);
  return spec.funcArgsToScVals("verify_and_pay", {
    proof: {
      a: hexToBytes(proofAbc.a),
      b: hexToBytes(proofAbc.b),
      c: hexToBytes(proofAbc.c),
    },
    pub_signals: signals.map((signal) => BigInt(signal)),
    policy_id: Number(signals[PUBLIC_SIGNAL_INDEX.policyId]),
    asset_id: Number(signals[PUBLIC_SIGNAL_INDEX.assetId]),
    amount: BigInt(signals[PUBLIC_SIGNAL_INDEX.amount]),
    recipient_id: BigInt(signals[PUBLIC_SIGNAL_INDEX.recipient]),
    action_id: BigInt(signals[PUBLIC_SIGNAL_INDEX.actionId]),
    packet_hash: BigInt(signals[PUBLIC_SIGNAL_INDEX.packetHash]),
    epoch: Number(signals[PUBLIC_SIGNAL_INDEX.epoch]),
  });
}

async function pollTransaction(server, txHash) {
  for (let i = 0; i < 30; i += 1) {
    const result = await server.getTransaction(txHash);
    if (result.status === "SUCCESS") return result;
    if (result.status === "FAILED" || result.status === "ERROR") {
      throw new Error(
        result.resultXdr || `transaction ${result.status.toLowerCase()}`,
      );
    }
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
  return { status: "PENDING" };
}

async function submitPaymentProof() {
  if (state.busy) return;
  state.busy = true;
  setButtonsDisabled(true);
  setStatus("submitting");
  appendLog("preparing payment submission");

  try {
    if (!window.StellarSdk) {
      throw new Error("Stellar SDK browser bundle is unavailable");
    }
    const api = window.freighterApi;
    if (!api?.signTransaction) {
      throw new Error("Freighter signing API not found");
    }
    if (!state.latestProofs.payment) {
      await generateProof("payment");
    }
    const latest = state.latestProofs.payment;
    if (!window.AnchorShieldConvert) {
      throw new Error("proof converter unavailable");
    }
    const proofAbc = window.AnchorShieldConvert.convertG16Proof(latest.proof);
    const signals = normalizeSignals(latest.publicSignals);
    appendLog(
      "submitting the exact in-browser proof (live-converted, no proof pool)",
    );
    const address = state.walletAddress || (await connectWallet());
    const deployments = await ensureDeployments();
    const specEntries = await ensureGatePaymentSpec();
    const StellarSdk = window.StellarSdk;
    const server = new StellarSdk.rpc.Server(TESTNET_RPC_URL);
    const account = await server.getAccount(address);
    const contract = new StellarSdk.Contract(
      deployments.contracts.gate_payment,
    );
    const args = paymentArgs(StellarSdk, specEntries, proofAbc, signals);
    const transaction = new StellarSdk.TransactionBuilder(account, {
      fee: "1000000",
      networkPassphrase: StellarSdk.Networks.TESTNET,
    })
      .addOperation(contract.call("verify_and_pay", ...args))
      .setTimeout(30)
      .build();
    appendLog("simulating gate_payment.verify_and_pay");
    const simulation = await server.simulateTransaction(transaction);
    if (simulation.error) {
      throw new Error(simulation.error);
    }
    const prepared = StellarSdk.rpc
      .assembleTransaction(transaction, simulation)
      .build();
    appendLog("requesting Freighter signature");
    const signed = await api.signTransaction(prepared.toXDR(), {
      networkPassphrase: StellarSdk.Networks.TESTNET,
      address,
    });
    if (signed.error) {
      throw new Error(signed.error.message || signed.error);
    }
    const signedTx = StellarSdk.TransactionBuilder.fromXDR(
      signed.signedTxXdr || signed,
      StellarSdk.Networks.TESTNET,
    );
    appendLog("submitting signed transaction to testnet RPC");
    const submitted = await server.sendTransaction(signedTx);
    if (submitted.status === "ERROR") {
      throw new Error(
        submitted.errorResultXdr || "transaction submission failed",
      );
    }
    const txHash = submitted.hash || submitted.txHash;
    const result = await pollTransaction(server, txHash);
    if (submitTx) {
      submitTx.textContent = shortHash(txHash);
      submitTx.title = txHash;
    }
    if (submitReplay) {
      submitReplay.textContent = "submit again to replay";
      submitReplay.className = "pending";
    }
    appendLog(`payment tx ${txHash}`);
    appendLog(
      `nullifier ${normalizeSignals(poolEntry.pub_signals)[PUBLIC_SIGNAL_INDEX.nullifier]}`,
    );
    appendLog(`RPC status ${result.status}`);
    markPaymentEpochUsed(poolEntry.epoch);
    setStatus("submitted", "success");
  } catch (error) {
    const replayed = /Nullifier|nullifier|used/i.test(error.message);
    if (submitReplay) {
      submitReplay.textContent = replayed ? "rejected" : "not run";
      submitReplay.className = replayed ? "success" : "pending";
    }
    setStatus(
      replayed ? "replay rejected" : "submit failed",
      replayed ? "success" : "error",
    );
    appendLog(error.message);
  } finally {
    state.busy = false;
    setButtonsDisabled(false);
  }
}

function shortHash(value) {
  if (!value || value.length <= 16) return value || "-";
  return `${value.slice(0, 10)}...${value.slice(-8)}`;
}

function setText(id, value) {
  const element = document.getElementById(id);
  if (element) element.textContent = value ?? "-";
}

function setHash(id, value) {
  const element = document.getElementById(id);
  if (!element) return;
  element.textContent = shortHash(value);
  element.title = value || "";
}

function setExplorerLink(selector, value, kind) {
  document.querySelectorAll(selector).forEach((link) => {
    if (!value) return;
    link.href = `https://stellar.expert/explorer/testnet/${kind}/${value}`;
    link.target = "_blank";
    link.rel = "noreferrer";
    link.title = value;
    const textNode = [...link.childNodes].find(
      (node) => node.nodeType === Node.TEXT_NODE,
    );
    if (textNode) textNode.textContent = shortHash(value);
  });
}

function renderTimeline(id, rows) {
  const list = document.getElementById(id);
  if (!list) return;
  list.replaceChildren(
    ...rows.map((row) => {
      const item = document.createElement("li");
      const label = document.createElement("span");
      const value = document.createElement("strong");
      label.textContent = row.label;
      value.textContent = row.value;
      value.className = row.className || "";
      value.title = row.title || row.value;
      item.append(label, value);
      return item;
    }),
  );
}

async function hydrateAnchorDashboard() {
  if (document.body.dataset.page !== "anchor") return;
  const mock = await ensureMockAnchor();
  setText("anchorAuth", mock.sep10.authenticated ? "authenticated" : "pending");
  const auth = document.getElementById("anchorAuth");
  if (auth) auth.className = mock.sep10.authenticated ? "success" : "pending";
  setHash("anchorQuote", mock.sep38.quoteId);
  setHash("anchorTransaction", mock.sep31.transactionId);
  setText("anchorWebhookCount", String(mock.webhooks.length));
  setText("anchorPolicy", mock.sep38.boundPolicyId);
  setText("anchorAmount", mock.sep38.amount);
  setHash("anchorPacketHash", mock.sep38.boundPacketHash);
  setHash("anchorActionBinding", mock.sep38.boundActionBinding);
  renderTimeline(
    "anchorWebhookList",
    mock.webhooks.map((webhook) => ({
      label: webhook.type,
      value: shortHash(webhook.txHash || webhook.id),
      title: webhook.txHash || webhook.id,
      className: "success",
    })),
  );
}

async function hydrateIssuerDashboard() {
  if (document.body.dataset.page !== "issuer") return;
  const payment = await loadJson("./data/payment-input.json");
  const rwa = await loadJson("./data/rwa-input.json");
  const deployments = await ensureDeployments();
  setText("issuerId", String(payment.issuer_id));
  setHash("issuerCredentialRoot", FLOW_CONFIG.payment.expected.credentialRoot);
  setHash("issuerSanctionsRoot", FLOW_CONFIG.payment.expected.sanctionsRoot);
  setHash("issuerRevocationRoot", FLOW_CONFIG.payment.expected.revocationRoot);
  const rows = document.getElementById("issuerPolicyRows");
  if (rows) {
    const items = [
      {
        gate: "payment",
        policy: payment.policy_id,
        asset: payment.asset_id,
        amount: payment.amount,
      },
      {
        gate: "rwa",
        policy: rwa.policy_id,
        asset: rwa.asset_id,
        amount: rwa.amount,
      },
    ];
    rows.replaceChildren(
      ...items.map((row) => {
        const tr = document.createElement("tr");
        const gateCell = document.createElement("td");
        const tag = document.createElement("span");
        tag.className = `tag ${row.gate === "payment" ? "tag-brand" : "tag-ok"}`;
        tag.textContent = row.gate;
        gateCell.append(tag);
        const policyCell = document.createElement("td");
        policyCell.className = "num";
        policyCell.textContent = row.policy;
        const assetCell = document.createElement("td");
        assetCell.className = "num";
        assetCell.textContent = row.asset;
        const amountCell = document.createElement("td");
        amountCell.className = "ta-r num";
        amountCell.textContent = row.amount;
        const rootsCell = document.createElement("td");
        rootsCell.textContent = deployments.contracts.issuer_registry
          ? "credential + sanctions + revocation"
          : "pending";
        tr.append(gateCell, policyCell, assetCell, amountCell, rootsCell);
        return tr;
      }),
    );
  }
}

async function hydrateRwaDashboard() {
  if (document.body.dataset.page !== "rwa") return;
  const mock = await ensureMockAnchor();
  const deployments = await ensureDeployments();
  setText("rwaAuthorization", mock.rwaIssuer.authorization);
  setText("rwaAsset", mock.rwaIssuer.assetId);
  setText("rwaAmount", mock.rwaIssuer.amount);
  setText("rwaRecipient", mock.rwaIssuer.recipientId);
  setText("rwaPolicy", mock.rwaIssuer.policyId);
  setHash("rwaActionBinding", mock.rwaIssuer.actionBinding);
  setHash("rwaAttestTx", mock.rwaIssuer.attestTx);
  setHash("rwaMintTx", mock.rwaIssuer.mintTx);
  setHash("rwaIdentityVerifier", deployments.contracts.identity_verifier);
  setHash(
    "rwaAdapter",
    deployments.contracts.rwa_compliance_adapter ||
      deployments.contracts.oz_compliance,
  );
  setHash("rwaToken", deployments.contracts.oz_rwa_token);
}

async function hydrateDeploymentLinks() {
  const deployments = await ensureDeployments();
  const paymentTx = deployments.payment_flow?.verify_and_pay_tx;
  const rwaTx =
    deployments.rwa_flow?.attest_for_mint_tx || deployments.rwa_flow?.mint_tx;
  setExplorerLink("#paymentTxLink, #onchainPaymentTx", paymentTx, "tx");
  setExplorerLink("#rwaTxLink, #onchainRwaTx", rwaTx, "tx");
  setText(
    "onchainPaymentFee",
    deployments.payment_flow?.fee_charged_stroops?.toLocaleString?.() ||
      String(deployments.payment_flow?.fee_charged_stroops || "pending"),
  );
  setText(
    "onchainRwaFee",
    deployments.rwa_flow?.attest_fee_charged_stroops?.toLocaleString?.() ||
      deployments.rwa_flow?.mint_fee_charged_stroops?.toLocaleString?.() ||
      String(
        deployments.rwa_flow?.attest_fee_charged_stroops ||
          deployments.rwa_flow?.mint_fee_charged_stroops ||
          "pending",
      ),
  );
  document.querySelectorAll("[data-contract-link]").forEach((link) => {
    const key = link.dataset.contractLink;
    const contractId =
      deployments.contracts[key] ||
      (key === "rwa_compliance_adapter"
        ? deployments.contracts.oz_compliance
        : undefined);
    if (!contractId) return;
    link.href = `https://stellar.expert/explorer/testnet/contract/${contractId}`;
    link.target = "_blank";
    link.rel = "noreferrer";
    link.title = contractId;
  });
  document.querySelectorAll("[data-contract-short]").forEach((node) => {
    const key = node.dataset.contractShort;
    const contractId =
      deployments.contracts[key] ||
      (key === "rwa_compliance_adapter"
        ? deployments.contracts.oz_compliance
        : undefined);
    if (!contractId) return;
    const textNode = [...node.childNodes].find(
      (child) => child.nodeType === Node.TEXT_NODE,
    );
    if (textNode) textNode.textContent = shortHash(contractId);
    node.title = contractId;
  });
}

async function hydrateVaultDashboard() {
  if (document.body.dataset.page !== "vault") return;
  const vault = await ensureDisclosureVault();
  const grant = vault.grants[0];
  setHash("vaultGrant", grant.id);
  setText("vaultSubject", grant.subject);
  setText("vaultExpiry", grant.expiresAt.slice(0, 10));
  setHash("vaultPacket", vault.packet.packetHash);
  setHash("vaultPaymentTx", vault.packet.paymentTx);
  setHash("vaultCipherHash", vault.encryption.encryptedPacketSha256);
  setText("vaultAlgorithm", vault.encryption.algorithm);
  renderTimeline(
    "vaultAuditLog",
    vault.auditLog.map((entry) => ({
      label: entry.action,
      value: entry.actor,
      title: `${entry.at} ${entry.target}`,
      className: "success",
    })),
  );
}

async function hydrateComplianceData() {
  const signatureFee = document.getElementById("signatureFee");
  if (signatureFee) {
    const deployments = await ensureDeployments();
    signatureFee.textContent =
      deployments.payment_flow?.fee_charged_stroops?.toString() || "pending";
  }
  if (disclosureState) {
    const disclosure = await loadJson("./data/disclosure-summary.json");
    disclosureState.textContent = disclosure.verified ? "verified" : "failed";
    disclosureState.className = disclosure.verified ? "success" : "error";
    if (disclosureHash) {
      disclosureHash.textContent = shortHash(disclosure.packetHash);
      disclosureHash.title = disclosure.packetHash;
    }
    if (disclosureTx) {
      disclosureTx.textContent = shortHash(disclosure.paymentTx);
      disclosureTx.title = disclosure.paymentTx;
    }
  }
  await hydrateAnchorDashboard();
  await hydrateIssuerDashboard();
  await hydrateRwaDashboard();
  await hydrateVaultDashboard();
  await hydrateDeploymentLinks();
}

document.querySelectorAll("[data-run-flow]").forEach((button) => {
  button.addEventListener("click", () => runFlow(button.dataset.runFlow));
});

failureButton?.addEventListener("click", runFailureChecks);
walletButton?.addEventListener("click", connectWallet);
submitPaymentButton?.addEventListener("click", submitPaymentProof);

window.addEventListener("load", async () => {
  try {
    if (document.querySelector("[data-run-flow]")) await ensureVkey();
    await hydrateComplianceData();
    setStatus("ready");
  } catch (error) {
    setStatus("asset error", "error");
    appendLog(error.message);
  }
});
