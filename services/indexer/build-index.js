const fs = require("fs");
const path = require("path");

const repo = path.resolve(__dirname, "..", "..");

const sources = [
  {
    flow: "payment",
    txKey: "verifyAndPayTx",
    contractKey: "m1GatePayment",
    hashKind: "packetHash",
    publicSignalsPath: "testdata/eligibility/public.json",
    rawPath: "services/indexer/raw/payment-events.json",
  },
  {
    flow: "rwa",
    txKey: "verifyAndTransferTx",
    contractKey: "m2GateRwa",
    hashKind: "termsHash",
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
  if (value.bytes !== undefined) return value.bytes;
  if (value.symbol !== undefined) return value.symbol;
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

function build() {
  const deployments = readJson("deployments/testnet.json");
  const indexedAt = new Date().toISOString();
  const events = sources.map((source) => {
    const raw = readJson(source.rawPath);
    const event = raw.contract_events.flat()[0];
    const values = dataMap(event);
    const publicSignals = readJson(source.publicSignalsPath);
    const deployment = deployments[source.contractKey];
    const txHash = deployment[source.txKey];

    return {
      id: `${source.flow}:${txHash}`,
      flow: source.flow,
      outcome: "approved",
      eventName: topics(event).join("."),
      contractId: event.contract_id,
      txHash,
      stellarExpertUrl: `https://stellar.expert/explorer/testnet/tx/${txHash}`,
      policyId: values.policy_id,
      actionId: values.action_id,
      assetId: values.asset_id,
      amount: values.amount,
      recipient: values.recipient,
      nullifier: values.nullifier,
      [source.hashKind]: publicSignals[1],
      actionBinding: publicSignals[3],
      piiOnChain: false,
    };
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
