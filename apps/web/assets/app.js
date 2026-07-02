const FLOW_CONFIG = {
  payment: {
    label: "payment",
    title: "Travel-rule payment proof",
    expected: {
      credentialRoot:
        "16968264084686815019409457797653750977845222036686396343320997197469327511410",
      policyId: "202",
      actionType: "0",
      assetId: "9001",
      amount: "250",
      recipient: "7000001",
      actionId: "424242",
      epoch: "12",
      sanctionsRoot:
        "39994942323213274039216662394779445131518412504488084715131745479549489087767",
      revocationRoot:
        "36194922186915982915970352615194123427043924252243819068188131198562594449181",
    },
    mutate: { index: 13, value: "251" },
    failureTarget: "paymentFailure",
  },
  rwa: {
    label: "RWA",
    title: "Regulated asset proof",
    expected: {
      credentialRoot:
        "16968264084686815019409457797653750977845222036686396343320997197469327511410",
      policyId: "303",
      actionType: "1",
      assetId: "9101",
      amount: "100",
      recipient: "8000001",
      actionId: "515151",
      epoch: "12",
      sanctionsRoot:
        "39994942323213274039216662394779445131518412504488084715131745479549489087767",
      revocationRoot:
        "36194922186915982915970352615194123427043924252243819068188131198562594449181",
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
const TESTNET_NETWORK_PASSPHRASE = "Test SDF Network ; September 2015";
const DEFAULT_ISSUER_ID = "101";
const FIELD_PRIME = BigInt(
  "52435875175126190479447740508185965837690552500527637822603658699938581184513",
);
const SUMSUB_SDK_SRC =
  "https://static.sumsub.com/idensic/static/sns-websdk-builder.js";
const KYC_USER_ID_KEY = "anchorshield.kycUserId";
const USED_PAYMENT_EPOCHS_KEY = "anchorshield.usedPaymentEpochs";
const WITNESS_INPUT_IDS = {
  payment: "paymentWitnessFile",
  rwa: "rwaWitnessFile",
};

const state = {
  vkey: null,
  deployments: null,
  gatePaymentSpec: null,
  latestProofs: {},
  mockAnchor: null,
  disclosureVault: null,
  poseidonParams: null,
  localInputs: {},
  walletAddress: "",
  onboarding: {
    userId: "",
    statusToken: "",
    kycCredential: null,
    voucherPublicKey: null,
    credentialVoucher: null,
    useBlindVoucher: false,
    userSecret: "",
    userCommitment: "",
    issuerId: "",
    credential: null,
    pollTimer: null,
  },
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
const witnessStatus = document.getElementById("witnessStatus");
const onboardWalletButton = document.getElementById("onboardWalletButton");
const onboardStartKyc = document.getElementById("onboardStartKyc");
const deriveSecretButton = document.getElementById("deriveSecretButton");
const enrollButton = document.getElementById("enrollButton");
const refreshCredentialButton = document.getElementById(
  "refreshCredentialButton",
);
const onboardingStatus = document.getElementById("onboardingStatus");

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

function setOnboardingStatus(text, cls = "pending") {
  if (onboardingStatus) {
    onboardingStatus.textContent = text;
    onboardingStatus.className = `pill ${cls}`;
  }
}

function setOptionalText(id, text, cls) {
  const element = document.getElementById(id);
  if (!element) return;
  element.textContent = text;
  if (cls) element.className = cls;
}

async function loadJson(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`failed to load ${url}`);
  }
  return response.json();
}

function bytesToHex(bytes) {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function bytesToBase64(bytes) {
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

async function sha256HexText(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(String(value)),
  );
  return bytesToHex(new Uint8Array(digest));
}

function poseidonMod(value) {
  const reduced = value % FIELD_PRIME;
  return reduced >= 0n ? reduced : reduced + FIELD_PRIME;
}

function poseidonPow5(value) {
  const square = poseidonMod(value * value);
  return poseidonMod(square * square * value);
}

async function ensurePoseidonParams() {
  if (!state.poseidonParams) {
    const params = await loadJson("./data/poseidon255-t3.json");
    if (params.schema !== "anchorshield.poseidon255.t3.v1") {
      throw new Error("invalid Poseidon constants asset");
    }
    state.poseidonParams = {
      constants: params.constants.map((value) => BigInt(value)),
      matrix: params.matrix.map((row) => row.map((value) => BigInt(value))),
      fullRounds: Number(params.full_rounds),
      partialRounds: Number(params.partial_rounds),
    };
  }
  return state.poseidonParams;
}

async function poseidon255T3(left, right) {
  const params = await ensurePoseidonParams();
  const t = 3;
  let poseidonState = [0n, BigInt(left), BigInt(right)];

  for (
    let round = 0;
    round < params.fullRounds + params.partialRounds;
    round += 1
  ) {
    const arked = poseidonState.map((value, index) =>
      poseidonMod(value + params.constants[round * t + index]),
    );
    const sbox =
      round < params.fullRounds / 2 ||
      round >= params.fullRounds / 2 + params.partialRounds
        ? arked.map(poseidonPow5)
        : [poseidonPow5(arked[0]), ...arked.slice(1)];
    poseidonState = params.matrix.map((row) =>
      poseidonMod(
        row.reduce(
          (sum, coefficient, index) => sum + coefficient * sbox[index],
          0n,
        ),
      ),
    );
  }

  return poseidonState[0].toString(10);
}

async function digestField(value) {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const field = BigInt(`0x${bytesToHex(new Uint8Array(digest))}`) % FIELD_PRIME;
  return (field === 0n ? 1n : field).toString(10);
}

function signedMessageBytes(value) {
  if (!value) throw new Error("Freighter returned an empty message signature");
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (Array.isArray(value)) return new Uint8Array(value);
  if (typeof value === "string") return new TextEncoder().encode(value);
  if (value.type === "Buffer" && Array.isArray(value.data)) {
    return new Uint8Array(value.data);
  }
  throw new Error("Freighter returned an unsupported message signature shape");
}

function signatureForWalletProof(value) {
  return typeof value === "string"
    ? value
    : bytesToBase64(signedMessageBytes(value));
}

async function walletProofMessage({
  action,
  address,
  statusToken,
  userCommitment = "",
  issuedAt,
}) {
  const lines = [
    "AnchorShield wallet authorization v1",
    "network:stellar-testnet",
    `action:${action}`,
    `wallet:${address}`,
    `status-token-sha256:${await sha256HexText(statusToken)}`,
  ];
  if (action === "enroll" || action === "resume") {
    lines.push(`user-commitment:${String(userCommitment)}`);
  }
  lines.push(`issued-at:${issuedAt}`);
  return lines.join("\n");
}

async function signWalletProof(
  action,
  { userCommitment = "", statusToken = state.onboarding.statusToken } = {},
) {
  const address = state.walletAddress || (await connectWallet());
  const api = window.freighterApi;
  if (!api?.signMessage) {
    throw new Error("Freighter signMessage API not found");
  }
  if (action !== "resume" && !statusToken) {
    throw new Error("KYC status token missing");
  }
  const issuedAt = new Date().toISOString();
  const message = await walletProofMessage({
    action,
    address,
    statusToken: statusToken || "",
    userCommitment,
    issuedAt,
  });
  const signed = await api.signMessage(message, {
    networkPassphrase: TESTNET_NETWORK_PASSPHRASE,
    address,
  });
  if (signed.error) {
    throw new Error(signed.error.message || signed.error);
  }
  if (signed.signerAddress && signed.signerAddress !== address) {
    throw new Error("Freighter signed with a different address");
  }
  return {
    message,
    issuedAt,
    signerAddress: signed.signerAddress || address,
    signature: signatureForWalletProof(signed.signedMessage),
  };
}

async function issuerIdForOnboarding() {
  try {
    const deployments = await ensureDeployments();
    return String(deployments.root_publish?.issuer_id || DEFAULT_ISSUER_ID);
  } catch {
    return DEFAULT_ISSUER_ID;
  }
}

async function fetchVoucherPublicKey() {
  if (state.onboarding.voucherPublicKey) {
    return state.onboarding.voucherPublicKey;
  }
  const response = await fetch("/api/kyc/voucher/pubkey");
  if (!response.ok) return null;
  const body = await response.json().catch(() => ({}));
  if (body.configured && body.publicKey?.n && body.publicKey?.e) {
    state.onboarding.voucherPublicKey = body.publicKey;
    state.onboarding.useBlindVoucher = Boolean(window.AnchorShieldBlind);
    return state.onboarding.useBlindVoucher ? body.publicKey : null;
  }
  state.onboarding.useBlindVoucher = false;
  return null;
}

function credentialTemplateFromKyc(credential, issuerId) {
  return {
    schema: "anchorshield.credential_template.v1",
    issuer_id: String(issuerId),
    kyc_passed: String(credential.kyc_passed),
    country: String(credential.country),
    age: String(credential.age),
    investor_type: "1",
    tx_limit: "1000",
    issued_at: "1",
    expires_at: "99",
  };
}

function templatesMatch(left, right) {
  const fields = [
    "schema",
    "issuer_id",
    "kyc_passed",
    "country",
    "age",
    "investor_type",
    "tx_limit",
    "issued_at",
    "expires_at",
  ];
  return fields.every((field) => String(left[field]) === String(right[field]));
}

async function foldHash(values) {
  let current = await poseidon255T3(values[0], values[1]);
  for (let i = 2; i < values.length; i += 1) {
    current = await poseidon255T3(current, values[i]);
  }
  return current;
}

async function credentialLeafFromTemplate(userCommitment, issuerId, template) {
  return foldHash([
    userCommitment,
    issuerId,
    template.kyc_passed,
    template.country,
    template.age,
    template.investor_type,
    template.tx_limit,
    template.issued_at,
    template.expires_at,
  ]);
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

function expectedSignalsForInput(flow, input) {
  return {
    policyId: flow.expected.policyId,
    actionType: flow.expected.actionType,
    assetId: flow.expected.assetId,
    amount: flow.expected.amount,
    recipient: flow.expected.recipient,
    actionId: flow.expected.actionId,
    epoch: String(input.epoch || flow.expected.epoch),
  };
}

function submitRootChecks(input) {
  const credential = state.onboarding.credential;
  if (credential && credential.user_commitment === input.user_commitment) {
    return {
      credentialRoot: credential.credential_root,
      sanctionsRoot: credential.sanctions_root,
      revocationRoot: credential.revocation_root,
    };
  }
  return {
    credentialRoot: FLOW_CONFIG.payment.expected.credentialRoot,
    sanctionsRoot: FLOW_CONFIG.payment.expected.sanctionsRoot,
    revocationRoot: FLOW_CONFIG.payment.expected.revocationRoot,
  };
}

function assertSubmitReady(signals, input) {
  const checks = submitRootChecks(input);
  for (const [name, expected] of Object.entries(checks)) {
    const actual = signals[PUBLIC_SIGNAL_INDEX[name]];
    if (actual !== expected) {
      throw new Error(
        `${name} is not the selected issuer root; refresh the credential path before submitting`,
      );
    }
  }
}

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
}

function setWitnessStatus(text, cls = "pending") {
  if (!witnessStatus) return;
  witnessStatus.textContent = text;
  witnessStatus.className = `section-sub ${cls}`;
}

async function parseJsonFile(file) {
  if (!file) throw new Error("select a witness JSON file");
  return JSON.parse(await file.text());
}

function rememberWitness(flowName, input) {
  const flow = FLOW_CONFIG[flowName];
  if (!flow) throw new Error(`unknown witness flow ${flowName}`);
  state.localInputs[flowName] = input;
  if (flowName === "payment" && submitEpoch) {
    submitEpoch.textContent = String(input.epoch || "-");
  }
  setWitnessStatus(`${flow.label} witness loaded from local file`, "success");
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

// Each demo submit needs a fresh nullifier, which is derived from the epoch. The witness is valid
// for any epoch in [issued_at, expires_at]; pick one not already used (locally or as the witness
// default) so re-running the demo doesn't replay a spent nullifier.
function pickFreshPaymentEpoch(input) {
  const lo = Number(input.issued_at) || 1;
  const hi = Number(input.expires_at) || 99;
  const used = usedPaymentEpochs();
  const original = Number(input.epoch);
  const free = [];
  for (let e = lo; e <= hi; e += 1) {
    if (e !== original && !used.has(e)) free.push(e);
  }
  return free.length ? free[Math.floor(Math.random() * free.length)] : original;
}

function actionTemplate(flowName) {
  const flow = FLOW_CONFIG[flowName];
  const payment = flowName === "payment";
  return {
    policy_id: flow.expected.policyId,
    kyc_required: "1",
    sanctions_required: "1",
    allowed_country: "566",
    min_age: "18",
    min_investor_type: payment ? "0" : "1",
    action_type: flow.expected.actionType,
    asset_id: flow.expected.assetId,
    amount: flow.expected.amount,
    recipient: flow.expected.recipient,
    action_id: flow.expected.actionId,
    epoch: flow.expected.epoch,
    packet_originator: payment ? "1111" : "3333",
    packet_beneficiary: payment ? "2222" : "4444",
    packet_amount: flow.expected.amount,
    packet_corridor: "566",
    packet_action_id: flow.expected.actionId,
  };
}

function onboardingWitnessInput(flowName) {
  const credential = state.onboarding.credential;
  if (!credential || !state.onboarding.userSecret) return null;
  return {
    issuer_id: credential.issuer_id,
    ...actionTemplate(flowName),
    sanctions_root: credential.sanctions_root,
    revocation_root: credential.revocation_root,
    user_secret: state.onboarding.userSecret,
    user_commitment: credential.user_commitment,
    ...credential.attributes,
    merkle_index: credential.merkle_index,
    merkle_siblings: credential.merkle_siblings,
    sanctions_low_value: credential.sanctions_low_value,
    sanctions_low_next: credential.sanctions_low_next,
    sanctions_low_index: credential.sanctions_low_index,
    sanctions_low_siblings: credential.sanctions_low_siblings,
    revocation_low_value: credential.revocation_low_value,
    revocation_low_next: credential.revocation_low_next,
    revocation_low_index: credential.revocation_low_index,
    revocation_low_siblings: credential.revocation_low_siblings,
  };
}

function loadWitnessInput(flowName) {
  const enrolledInput = onboardingWitnessInput(flowName);
  if (enrolledInput) {
    return cloneJson(enrolledInput);
  }
  const input = state.localInputs[flowName];
  if (!input) {
    throw new Error(
      `complete wallet onboarding or load a local ${FLOW_CONFIG[flowName].label} witness JSON`,
    );
  }
  return cloneJson(input);
}

function markActiveFlow(flowName) {
  document.querySelectorAll("[data-flow-card]").forEach((card) => {
    card.classList.toggle("active", card.dataset.flowCard === flowName);
  });
}

function setButtonsDisabled(disabled) {
  document
    .querySelectorAll(
      "[data-run-flow], #failureButton, #walletButton, #submitPaymentButton, #onboardWalletButton, #onboardStartKyc, #deriveSecretButton, #enrollButton, #refreshCredentialButton",
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

  if (state.onboarding.credential && state.onboarding.userSecret) {
    if (log) appendLog("refreshing issuer Merkle path");
    await fetchOnboardingCredential(state.walletAddress || "");
  }

  if (log) appendLog(`loading ${flow.label} witness`);
  const input = loadWitnessInput(flowName);
  if (flowName === "payment") {
    input.epoch = String(pickFreshPaymentEpoch(input));
  }
  const expected = expectedSignalsForInput(flow, input);
  if (flowName === "payment") {
    if (submitEpoch) submitEpoch.textContent = String(input.epoch || "-");
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
  const elapsed = Math.round(performance.now() - start);
  const proofHash = await sha256Short(proof);
  state.latestProofs[flowName] = { proof, publicSignals, input };
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
    if (walletState) walletState.textContent = "unavailable";
    if (walletAddress) walletAddress.textContent = "Freighter API not found";
    setOptionalText("onboardWalletStatus", "Freighter API not found", "error");
    return;
  }

  try {
    if (api.isConnected) {
      const connected = await api.isConnected();
      if (connected.error || connected.isConnected === false) {
        if (walletState) walletState.textContent = "unavailable";
        if (walletAddress) {
          walletAddress.textContent =
            connected.error?.message || "Freighter not installed";
        }
        setOptionalText(
          "onboardWalletStatus",
          connected.error?.message || "Freighter not installed",
          "error",
        );
        return;
      }
    }
    const access = await api.requestAccess();
    if (access.error) {
      throw new Error(access.error.message);
    }
    if (walletState) walletState.textContent = "connected";
    state.walletAddress = access.address || "";
    if (walletAddress) {
      walletAddress.textContent = state.walletAddress || "address unavailable";
    }
    setOptionalText(
      "onboardWalletStatus",
      state.walletAddress
        ? shortHash(state.walletAddress)
        : "address unavailable",
      state.walletAddress ? "hash success" : "error",
    );
    return state.walletAddress;
  } catch (error) {
    if (walletState) walletState.textContent = "denied";
    if (walletAddress) walletAddress.textContent = error.message;
    setOptionalText("onboardWalletStatus", error.message, "error");
    throw error;
  }
}

let onboardingConnectInFlight = false;

async function connectOnboardingWallet() {
  // Guard against a second click (top-bar or onboarding button) starting a
  // concurrent connect -> derive -> resume chain while one is in flight.
  if (onboardingConnectInFlight) return state.walletAddress;
  onboardingConnectInFlight = true;
  try {
    const address = await connectWallet();
    if (address) {
      await deriveOnboardingSecret();
    }
    return address;
  } finally {
    onboardingConnectInFlight = false;
  }
}

function setOnboardingButtonsDisabled(disabled) {
  [
    walletButton,
    onboardWalletButton,
    onboardStartKyc,
    deriveSecretButton,
    enrollButton,
    refreshCredentialButton,
  ].forEach((button) => {
    if (button) button.disabled = disabled;
  });
}

function loadSumsubSdk() {
  return new Promise((resolve, reject) => {
    if (window.snsWebSdk) return resolve();
    const script = document.createElement("script");
    script.src = SUMSUB_SDK_SRC;
    script.onload = () => resolve();
    script.onerror = () => reject(new Error("failed to load Sumsub WebSDK"));
    document.head.appendChild(script);
  });
}

async function mintKycToken(existingUserId) {
  const voucherPublicKey =
    existingUserId && state.onboarding.statusToken
      ? state.onboarding.voucherPublicKey
      : await fetchVoucherPublicKey().catch(() => null);
  if (!existingUserId && voucherPublicKey) {
    const response = await fetch("/api/kyc/voucher/session", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(body.error || `voucher session HTTP ${response.status}`);
    }
    state.onboarding.voucherPublicKey = body.publicKey || voucherPublicKey;
    state.onboarding.useBlindVoucher = true;
    return body;
  }
  const requestBody =
    existingUserId && state.onboarding.statusToken
      ? { userId: existingUserId, statusToken: state.onboarding.statusToken }
      : {};
  const response = await fetch("/api/kyc/token", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(requestBody),
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(body.error || `KYC token HTTP ${response.status}`);
  }
  return body;
}

function stopOnboardingKycPoll() {
  if (state.onboarding.pollTimer) {
    clearInterval(state.onboarding.pollTimer);
    state.onboarding.pollTimer = null;
  }
}

async function pollOnboardingKycStatus() {
  const token = state.onboarding.statusToken;
  if (!token) throw new Error("KYC status token missing");
  const response = await fetch("/api/kyc/status", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ statusToken: token }),
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(body.error || `KYC status HTTP ${response.status}`);
  }
  const answer = body.reviewAnswer;
  setOptionalText(
    "onboardKycStatus",
    answer ? `review: ${answer}` : "verification in progress",
    answer === "GREEN" ? "success" : answer === "RED" ? "error" : "pending",
  );
  if (answer === "GREEN" && body.credential) {
    state.onboarding.kycCredential = body.credential;
    setOptionalText(
      "onboardKycCredential",
      `kyc_passed=${body.credential.kyc_passed} | country=${body.credential.country} | age=${body.credential.age}`,
      "success",
    );
    stopOnboardingKycPoll();
    setOnboardingStatus("KYC green", "success");
  }
  if (answer === "RED") {
    // Final reject: stop the interval. A retry inside the Sumsub widget still
    // re-polls via the onApplicantStatusChanged event handler.
    stopOnboardingKycPoll();
    setOnboardingStatus("KYC rejected", "error");
  }
  return body;
}

async function startOnboardingKyc() {
  setOnboardingButtonsDisabled(true);
  setOnboardingStatus("KYC starting");
  setOptionalText("onboardKycStatus", "minting access token", "pending");
  try {
    if (state.onboarding.credential) {
      showOnboardingCredential(
        state.onboarding.credential,
        "credential on-chain",
        "Wallet already verified - credential on-chain",
      );
      setOptionalText(
        "onboardKycStatus",
        "wallet already verified - credential on-chain",
        "success",
      );
      return;
    }
    const existingUserId = localStorage.getItem(KYC_USER_ID_KEY);
    const token = await mintKycToken(existingUserId);
    state.onboarding.userId = token.userId;
    state.onboarding.statusToken = token.statusToken;
    localStorage.setItem(KYC_USER_ID_KEY, token.userId);
    if (!state.onboarding.statusToken) throw new Error("status token missing");
    setOptionalText("onboardKycStatus", "launching verification", "pending");
    await loadSumsubSdk();
    const sdk = window.snsWebSdk
      .init(token.token, async () => {
        const refreshed = await mintKycToken(state.onboarding.userId);
        state.onboarding.statusToken = refreshed.statusToken;
        return refreshed.token;
      })
      .withConf({ lang: "en" })
      .withOptions({ addViewportTag: false, adaptIframeHeight: true })
      .on("idCheck.onApplicantStatusChanged", () =>
        pollOnboardingKycStatus().catch(() => undefined),
      )
      .on("idCheck.onError", (event) =>
        setOptionalText(
          "onboardKycStatus",
          `widget error: ${event?.error || JSON.stringify(event)}`,
          "error",
        ),
      )
      .build();
    sdk.launch("#onboardSumsubWebsdk");
    setOptionalText("onboardKycStatus", "verification in progress", "pending");
    stopOnboardingKycPoll();
    state.onboarding.pollTimer = setInterval(
      () => pollOnboardingKycStatus().catch(() => undefined),
      5000,
    );
  } catch (error) {
    setOnboardingStatus("KYC failed", "error");
    setOptionalText("onboardKycStatus", error.message, "error");
  } finally {
    setOnboardingButtonsDisabled(false);
  }
}

async function deriveOnboardingSecret() {
  setOnboardingButtonsDisabled(true);
  setOnboardingStatus("signature requested");
  try {
    const address = state.walletAddress || (await connectWallet());
    const api = window.freighterApi;
    if (!api?.signMessage) {
      throw new Error("Freighter signMessage API not found");
    }
    const issuerId = await issuerIdForOnboarding();
    const message = [
      "AnchorShield self-serve eligibility v1",
      "network:stellar-testnet",
      `issuer:${issuerId}`,
      `address:${address}`,
      "purpose:derive-user-secret",
    ].join("\n");
    const signed = await api.signMessage(message, {
      networkPassphrase: TESTNET_NETWORK_PASSPHRASE,
      address,
    });
    if (signed.error) {
      throw new Error(signed.error.message || signed.error);
    }
    if (signed.signerAddress && signed.signerAddress !== address) {
      throw new Error("Freighter signed with a different address");
    }
    const signature = bytesToHex(signedMessageBytes(signed.signedMessage));
    const userSecret = await digestField({
      domain: "anchorshield.wallet-secret.v1",
      address,
      issuer_id: issuerId,
      network: "testnet",
      message,
      signature,
    });
    const userCommitment = await poseidon255T3(userSecret, issuerId);
    if (
      state.onboarding.userCommitment &&
      state.onboarding.userCommitment !== userCommitment
    ) {
      state.onboarding.credential = null;
      state.onboarding.credentialVoucher = null;
      setOptionalText("onboardCredentialRoot", "root pending", "pending");
      setOptionalText("onboardMerkleIndex", "index pending", "pending");
    }
    state.onboarding.userSecret = userSecret;
    state.onboarding.userCommitment = userCommitment;
    state.onboarding.issuerId = issuerId;
    setOptionalText("onboardCommitment", shortHash(userCommitment), "hash");
    setOnboardingStatus("secret derived", "success");
    setWitnessStatus("Wallet secret derived in browser memory", "success");
    await resumeOnboardingCredential(address);
  } catch (error) {
    setOnboardingStatus("signature failed", "error");
    setOptionalText("onboardCommitment", error.message, "error");
    throw error;
  } finally {
    setOnboardingButtonsDisabled(false);
  }
}

async function fetchResumeCredential(address) {
  if (!state.onboarding.userCommitment) {
    throw new Error("derive wallet secret before credential lookup");
  }
  const response = await fetch("/api/credential", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      wallet: address,
      userCommitment: state.onboarding.userCommitment,
      walletProof: await signWalletProof("resume", {
        userCommitment: state.onboarding.userCommitment,
        statusToken: "",
      }),
    }),
  });
  const body = await response.json().catch(() => ({}));
  if (response.status === 404) {
    return null;
  }
  if (!response.ok) {
    throw new Error(body.error || `credential resume HTTP ${response.status}`);
  }
  state.onboarding.credential = body.credential;
  return body.credential;
}

async function resumeOnboardingCredential(address) {
  const credential = await fetchResumeCredential(address);
  if (!credential) {
    state.onboarding.credential = null;
    setOptionalText(
      "onboardKycStatus",
      state.onboarding.kycCredential
        ? "KYC green - enroll wallet credential"
        : "wallet not enrolled - verify identity to enroll",
      state.onboarding.kycCredential ? "success" : "pending",
    );
    setOnboardingStatus(
      state.onboarding.kycCredential ? "ready to enroll" : "KYC required",
      state.onboarding.kycCredential ? "success" : "pending",
    );
    return null;
  }
  setOptionalText(
    "onboardKycStatus",
    "wallet already verified - credential on-chain",
    "success",
  );
  setOptionalText(
    "onboardKycCredential",
    `kyc_passed=${credential.attributes.kyc_passed} | country=${credential.attributes.country} | age=${credential.attributes.age}`,
    "success",
  );
  showOnboardingCredential(
    credential,
    "credential on-chain",
    "Wallet already verified - credential on-chain",
  );
  return credential;
}

async function buildCredentialVoucher() {
  if (!state.onboarding.useBlindVoucher) return null;
  if (!window.AnchorShieldBlind) {
    throw new Error("blind voucher helper unavailable");
  }
  if (!state.onboarding.kycCredential) {
    const status = await pollOnboardingKycStatus();
    if (status.reviewAnswer !== "GREEN" || !status.credential) {
      throw new Error("KYC must be GREEN before blind voucher issuance");
    }
  }
  const issuerId = state.onboarding.issuerId || (await issuerIdForOnboarding());
  const template = credentialTemplateFromKyc(
    state.onboarding.kycCredential,
    issuerId,
  );
  const credentialLeaf = await credentialLeafFromTemplate(
    state.onboarding.userCommitment,
    issuerId,
    template,
  );
  const blinded = await window.AnchorShieldBlind.blindMessage(
    credentialLeaf,
    state.onboarding.voucherPublicKey,
  );
  const response = await fetch("/api/kyc/voucher", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      statusToken: state.onboarding.statusToken,
      blinded: blinded.blinded,
    }),
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(body.error || `voucher HTTP ${response.status}`);
  }
  if (!templatesMatch(template, body.credentialTemplate || {})) {
    throw new Error("voucher template does not match KYC status");
  }
  const signature = window.AnchorShieldBlind.unblind(
    body.blindSignature,
    blinded.r,
    state.onboarding.voucherPublicKey,
  );
  const valid = await window.AnchorShieldBlind.verify(
    credentialLeaf,
    signature,
    state.onboarding.voucherPublicKey,
  );
  if (!valid) {
    throw new Error("blind voucher signature failed local verification");
  }
  state.onboarding.credentialVoucher = {
    signature,
    credentialTemplate: body.credentialTemplate,
    credentialTemplateMac: body.credentialTemplateMac,
  };
  setOptionalText("onboardKycStatus", "blind voucher ready", "success");
  return state.onboarding.credentialVoucher;
}

async function enrollOnboardingCredential() {
  setOnboardingButtonsDisabled(true);
  setOnboardingStatus("enrolling");
  try {
    if (state.onboarding.credential) {
      showOnboardingCredential(
        state.onboarding.credential,
        "credential on-chain",
        "Wallet already verified - credential on-chain",
      );
      return;
    }
    if (!state.onboarding.statusToken) {
      throw new Error("complete KYC before enrollment");
    }
    if (!state.onboarding.userCommitment) {
      await deriveOnboardingSecret();
    }
    const voucher = await buildCredentialVoucher();
    const legacyAddress = voucher
      ? ""
      : state.walletAddress || (await connectWallet());
    const response = await fetch("/api/enroll", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(
        voucher
          ? {
              userCommitment: state.onboarding.userCommitment,
              voucher,
            }
          : {
              wallet: legacyAddress,
              userCommitment: state.onboarding.userCommitment,
              statusToken: state.onboarding.statusToken,
              walletProof: await signWalletProof("enroll", {
                userCommitment: state.onboarding.userCommitment,
              }),
            },
      ),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(body.error || `enroll HTTP ${response.status}`);
    }
    state.onboarding.credential = body.credential;
    showOnboardingCredential(
      body.credential,
      "credential ready",
      "Self-serve credential path loaded from issuer",
    );
  } catch (error) {
    setOnboardingStatus("enroll failed", "error");
    setOptionalText("onboardCredentialRoot", error.message, "error");
  } finally {
    setOnboardingButtonsDisabled(false);
  }
}

async function fetchOnboardingCredential(address) {
  if (state.onboarding.credentialVoucher) {
    const response = await fetch("/api/credential", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        userCommitment: state.onboarding.userCommitment,
        voucher: state.onboarding.credentialVoucher,
      }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(body.error || `credential HTTP ${response.status}`);
    }
    state.onboarding.credential = body.credential;
    return body.credential;
  }
  if (state.onboarding.userCommitment && address) {
    const credential = await fetchResumeCredential(address);
    if (credential) return credential;
  }
  if (!state.onboarding.statusToken) {
    throw new Error("KYC status token missing");
  }
  const response = await fetch("/api/credential", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      wallet: address,
      statusToken: state.onboarding.statusToken,
      walletProof: await signWalletProof("credential"),
    }),
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(body.error || `credential HTTP ${response.status}`);
  }
  state.onboarding.credential = body.credential;
  return body.credential;
}

function showOnboardingCredential(credential, statusText, witnessText) {
  setOptionalText(
    "onboardCredentialRoot",
    shortHash(credential.credential_root),
    "hash",
  );
  const anonymitySetSize = Number(credential.anonymity_set_size || 0);
  const anonymityText = anonymitySetSize
    ? `index ${credential.merkle_index} | set ${anonymitySetSize}`
    : `index ${credential.merkle_index}`;
  setOptionalText(
    "onboardMerkleIndex",
    anonymityText,
    anonymitySetSize > 0 && anonymitySetSize < 32
      ? "num pending"
      : "num success",
  );
  setOnboardingStatus(statusText, "success");
  setWitnessStatus(witnessText, "success");
}

async function refreshOnboardingCredential() {
  setOnboardingButtonsDisabled(true);
  setOnboardingStatus("refreshing path");
  try {
    const address = state.walletAddress || (await connectWallet());
    const credential = await fetchOnboardingCredential(address);
    showOnboardingCredential(
      credential,
      "fresh path ready",
      "Fresh issuer path loaded",
    );
  } catch (error) {
    setOnboardingStatus("refresh failed", "error");
    setOptionalText("onboardCredentialRoot", error.message, "error");
  } finally {
    setOnboardingButtonsDisabled(false);
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
    assertSubmitReady(signals, latest.input);
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
    appendLog(`payment tx ${txHash}`);
    appendLog(`nullifier ${signals[PUBLIC_SIGNAL_INDEX.nullifier]}`);
    appendLog(`RPC status ${result.status}`);
    if (result.status !== "SUCCESS") {
      // Poll timed out before confirmation: do not claim success and do not
      // burn the local epoch — the transaction may still land, so keep the
      // epoch replayable and point the user at the tx hash.
      appendLog(
        "transaction not confirmed yet - check the tx hash before retrying",
      );
      setStatus("tx pending, not confirmed");
      return;
    }
    if (submitReplay) {
      submitReplay.textContent = "submit again to replay";
      submitReplay.className = "pending";
    }
    markPaymentEpochUsed(signals[PUBLIC_SIGNAL_INDEX.epoch]);
    setStatus("submitted", "success");
  } catch (error) {
    const replayed = /Nullifier|nullifier|used/i.test(error.message);
    if (replayed && state.latestProofs.payment) {
      markPaymentEpochUsed(
        normalizeSignals(state.latestProofs.payment.publicSignals)[
          PUBLIC_SIGNAL_INDEX.epoch
        ],
      );
    }
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
  const deployments = await ensureDeployments();
  setText("issuerId", String(deployments.root_publish?.issuer_id || "101"));
  setHash("issuerCredentialRoot", FLOW_CONFIG.payment.expected.credentialRoot);
  setHash("issuerSanctionsRoot", FLOW_CONFIG.payment.expected.sanctionsRoot);
  setHash("issuerRevocationRoot", FLOW_CONFIG.payment.expected.revocationRoot);
  const rows = document.getElementById("issuerPolicyRows");
  if (rows) {
    const items = [
      {
        gate: "payment",
        policy: FLOW_CONFIG.payment.expected.policyId,
        asset: FLOW_CONFIG.payment.expected.assetId,
        amount: FLOW_CONFIG.payment.expected.amount,
      },
      {
        gate: "rwa",
        policy: FLOW_CONFIG.rwa.expected.policyId,
        asset: FLOW_CONFIG.rwa.expected.assetId,
        amount: FLOW_CONFIG.rwa.expected.amount,
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
  const directoryRows = document.getElementById("issuerDirectoryRows");
  if (directoryRows) {
    try {
      const response = await fetch("/api/issuers");
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const directory = await response.json();
      const issuers = Array.isArray(directory.issuers) ? directory.issuers : [];
      directoryRows.replaceChildren(
        ...issuers.map((issuer) => {
          const tr = document.createElement("tr");
          const idCell = document.createElement("td");
          idCell.className = "num";
          idCell.textContent = String(issuer.issuer_id || "-");
          const nameCell = document.createElement("td");
          nameCell.textContent =
            issuer.metadata?.name ||
            issuer.metadata_error ||
            "metadata pending";
          const jurisdictionCell = document.createElement("td");
          jurisdictionCell.textContent = issuer.metadata?.jurisdiction || "-";
          const licenseCell = document.createElement("td");
          licenseCell.textContent = issuer.metadata?.license_id || "-";
          const metadataCell = document.createElement("td");
          if (issuer.metadata_uri) {
            const link = document.createElement("a");
            link.className = "hash";
            link.href = issuer.metadata_uri;
            link.target = "_blank";
            link.rel = "noreferrer";
            link.textContent = shortHash(issuer.metadata_uri);
            link.title = issuer.metadata_uri;
            metadataCell.append(link);
          } else {
            metadataCell.textContent = "-";
          }
          tr.append(
            idCell,
            nameCell,
            jurisdictionCell,
            licenseCell,
            metadataCell,
          );
          return tr;
        }),
      );
    } catch (error) {
      const tr = document.createElement("tr");
      const cell = document.createElement("td");
      cell.colSpan = 5;
      cell.textContent = `issuer directory unavailable: ${error.message}`;
      tr.append(cell);
      directoryRows.replaceChildren(tr);
    }
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
  if (document.body.dataset.page !== "auditor") return;
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

for (const [flowName, inputId] of Object.entries(WITNESS_INPUT_IDS)) {
  const input = document.getElementById(inputId);
  input?.addEventListener("change", async () => {
    try {
      rememberWitness(flowName, await parseJsonFile(input.files?.[0]));
    } catch (error) {
      setWitnessStatus(error.message, "error");
    }
  });
}

document.querySelectorAll("[data-run-flow]").forEach((button) => {
  button.addEventListener("click", () => runFlow(button.dataset.runFlow));
});

failureButton?.addEventListener("click", runFailureChecks);
walletButton?.addEventListener("click", () => {
  if (onboardWalletButton) {
    connectOnboardingWallet().catch(() => undefined);
    return;
  }
  connectWallet().catch(() => undefined);
});
onboardWalletButton?.addEventListener("click", () =>
  connectOnboardingWallet().catch(() => undefined),
);
onboardStartKyc?.addEventListener("click", startOnboardingKyc);
deriveSecretButton?.addEventListener("click", () =>
  deriveOnboardingSecret().catch(() => undefined),
);
enrollButton?.addEventListener("click", enrollOnboardingCredential);
refreshCredentialButton?.addEventListener("click", refreshOnboardingCredential);
submitPaymentButton?.addEventListener("click", submitPaymentProof);

window.AnchorShieldOnboarding = {
  async witnessInput(flowName) {
    if (state.onboarding.credential && state.onboarding.userSecret) {
      await fetchOnboardingCredential(state.walletAddress || "");
    }
    const input = onboardingWitnessInput(flowName);
    if (!input) {
      throw new Error(
        `complete wallet onboarding or load a local ${FLOW_CONFIG[flowName].label} witness JSON`,
      );
    }
    return cloneJson(input);
  },
  refreshCredential: refreshOnboardingCredential,
};

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
