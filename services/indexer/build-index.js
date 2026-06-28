const fs = require("fs");
const path = require("path");

const repo = path.resolve(__dirname, "..", "..");

const sources = [
  {
    flow: "payment",
    tx: (deployments) => deployments.payment_flow.verify_and_pay_tx,
    contract: (deployments) => deployments.contracts.gate_payment,
    hashKind: "packetHash",
    eventHashKey: "packet_hash",
    topic: "approved",
    publicSignalsPath: "testdata/eligibility/public.json",
    rawPath: "services/indexer/raw/payment-events.json",
  },
  {
    flow: "rwa",
    tx: (deployments) =>
      deployments.rwa_flow.attest_for_mint_tx || deployments.rwa_flow.mint_tx,
    relatedTx: (deployments) => deployments.rwa_flow.mint_tx,
    contract: (deployments) =>
      deployments.rwa_flow.attest_for_mint_tx
        ? deployments.contracts.identity_verifier
        : deployments.contracts.oz_rwa_token,
    hashKind: "termsHash",
    eventHashKey: "terms_hash",
    topic: "mint_authorized",
    publicSignalsPath: "testdata/rwa/public.json",
    rawPath: "services/indexer/raw/rwa-events.json",
  },
];

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(repo, relativePath), "utf8"));
}

function writeJson(relativePath, value) {
  const file = path.join(repo, relativePath);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function scVal(value) {
  if (value.u32 !== undefined) return String(value.u32);
  if (value.u128 !== undefined) return value.u128;
  if (value.i128 !== undefined) return value.i128;
  if (value.u64 !== undefined) return value.u64;
  if (value.bytes !== undefined) return value.bytes;
  if (value.address !== undefined) return value.address;
  if (value.symbol !== undefined) return value.symbol;
  if (value.string !== undefined) return value.string;
  return JSON.stringify(value);
}

function dataMap(event) {
  const entries = event.body.v0.data.map;
  return Object.fromEntries(
    entries.map((entry) => [entry.key.symbol, scVal(entry.val)]),
  );
}

function topics(event) {
  return event.body.v0.topics.map(scVal);
}

function signalHex(signal) {
  return BigInt(signal).toString(16).padStart(64, "0");
}

function selectEvent(raw, source) {
  const events = raw.contract_events.flat();
  const event = events.find((candidate) => {
    const candidateTopics = topics(candidate);
    return (
      candidate.contract_id === source.contract(readJson("deployments/testnet-hardened.json")) &&
      candidateTopics.includes(source.topic) &&
      candidate.body.v0.data.map
    );
  });
  if (!event) {
    throw new Error(`indexed event not found for ${source.flow}`);
  }
  return event;
}

function build() {
  const deployments = readJson("deployments/testnet-hardened.json");
  const indexedAt = new Date().toISOString();
  const events = sources.map((source) => {
    const raw = readJson(source.rawPath);
    const event = selectEvent(raw, source);
    const values = dataMap(event);
    const publicSignals = readJson(source.publicSignalsPath);
    const txHash = source.tx(deployments);
    const contractId = source.contract(deployments);
    const relatedTxHash = source.relatedTx ? source.relatedTx(deployments) : undefined;
    const proofBoundHash = signalHex(publicSignals[1]);
    const proofActionBinding = signalHex(publicSignals[3]);

    const indexed = {
      id: `${source.flow}:${txHash}`,
      flow: source.flow,
      outcome: "approved",
      eventName: topics(event).join("."),
      contractId: event.contract_id || contractId,
      txHash,
      stellarExpertUrl: `https://stellar.expert/explorer/testnet/tx/${txHash}`,
      policyId: values.policy_id,
      actionId: values.action_id,
      assetId: values.asset_id,
      amount: values.amount,
      recipient: values.recipient,
      nullifier: values.nullifier,
      [source.hashKind]: publicSignals[1],
      [`${source.hashKind}Hex`]: proofBoundHash,
      eventBoundHash: values[source.eventHashKey],
      eventBoundHashMatches: values[source.eventHashKey] === proofBoundHash,
      actionBinding: publicSignals[3],
      actionBindingHex: proofActionBinding,
      eventActionBinding: values.action_binding,
      eventActionBindingMatches: values.action_binding === proofActionBinding,
      piiOnChain: false,
    };
    if (relatedTxHash && relatedTxHash !== txHash) {
      indexed.relatedMintTx = relatedTxHash;
      indexed.relatedMintUrl = `https://stellar.expert/explorer/testnet/tx/${relatedTxHash}`;
    }
    return indexed;
  });

  const index = {
    network: "testnet",
    indexedAt,
    source: "stellar tx fetch events",
    events,
  };

  writeJson("services/indexer/compliance-events.json", index);
  writeJson("apps/web/data/compliance-events.json", index);
  console.log(JSON.stringify(index, null, 2));
}

build();
