#!/usr/bin/env node

const path = require("path");
const sdk = require("../sdk/src");

function usage() {
  console.log(`anchorshield <command>

Commands:
  inspect-public --public <public.json>
  validate-action --input <input.json> --public <public.json> [--flow payment|rwa]
  soroban-args --cli-args <cli-args.json>
  events --file <compliance-events.json>
  disclosure verify --summary <summary.json>
  gate payment --contract <id> --cli-args <cli-args.json> --input <input.json> [--network testnet] [--source-account <account>] [--out-dir .m6/invoke/payment]
  gate rwa --contract <id> --cli-args <cli-args.json> --input <input.json> [--network testnet] [--source-account <account>] [--out-dir .m6/invoke/rwa]`);
}

function args(argv) {
  const parsed = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const value = argv[i];
    if (value.startsWith("--")) {
      const key = value.slice(2);
      const next = argv[i + 1];
      if (!next || next.startsWith("--")) {
        parsed[key] = true;
      } else {
        parsed[key] = next;
        i += 1;
      }
    } else {
      parsed._.push(value);
    }
  }
  return parsed;
}

function required(options, name) {
  if (!options[name] || typeof options[name] !== "string") {
    throw new Error(`missing --${name}`);
  }
  return options[name];
}

function printJson(value) {
  console.log(JSON.stringify(value, null, 2));
}

function quote(value) {
  return `'${String(value).replace(/'/g, "'\\''")}'`;
}

function fileArg(name, value) {
  return `--${name} ${quote(value)}`;
}

function buildStellarCommand(flow, contract, cliArgsFile, inputFile, network, sourceAccount, outDir) {
  const cliArgs = sdk.readJson(cliArgsFile);
  const input = sdk.readJson(inputFile);
  const parsed =
    flow === "payment"
      ? sdk.assertPaymentAction(input, cliArgs.pub_signals)
      : sdk.assertRwaAction(input, cliArgs.pub_signals);
  const hashName = flow === "payment" ? "packet_hash" : "terms_hash";
  const fnName = flow === "payment" ? "verify_and_pay" : "verify_and_transfer";
  const hashValue = parsed.packet_hash;
  const vkPath = path.join(outDir, "vk.json");
  const proofPath = path.join(outDir, "proof.json");
  const publicPath = path.join(outDir, "pub_signals.json");

  sdk.writeJson(vkPath, cliArgs.vk);
  sdk.writeJson(proofPath, cliArgs.proof);
  sdk.writeJson(
    publicPath,
    sdk.formatImplicitCliPubSignals(cliArgs.pub_signals),
  );

  return [
    "stellar contract invoke",
    `--network ${network}`,
    `--source-account ${sourceAccount}`,
    "--send no",
    `--id ${contract}`,
    `-- ${fnName}`,
    fileArg("vk-file-path", vkPath),
    fileArg("proof-file-path", proofPath),
    fileArg("pub_signals-file-path", publicPath),
    `--policy_id ${parsed.policy_id}`,
    `--asset_id ${parsed.asset_id}`,
    `--amount ${parsed.amount}`,
    `--recipient ${parsed.recipient}`,
    `--action_id ${parsed.action_id}`,
    `--${hashName} ${hashValue}`,
    `--epoch ${parsed.epoch}`,
  ].join(" ");
}

async function main() {
  const options = args(process.argv.slice(2));
  const [command, subcommand] = options._;

  if (!command || command === "help" || command === "--help") {
    usage();
    return;
  }

  if (command === "inspect-public") {
    printJson(sdk.parsePublicSignals(sdk.readJson(required(options, "public"))));
    return;
  }

  if (command === "validate-action") {
    const input = sdk.readJson(required(options, "input"));
    const publicSignals = sdk.readJson(required(options, "public"));
    const flow = options.flow || (input.action_type === sdk.RWA_ACTION_TYPE ? "rwa" : "payment");
    const parsed =
      flow === "rwa"
        ? sdk.assertRwaAction(input, publicSignals)
        : sdk.assertPaymentAction(input, publicSignals);
    printJson({ flow, valid: true, action_id: parsed.action_id, policy_id: parsed.policy_id });
    return;
  }

  if (command === "soroban-args") {
    const cliArgs = sdk.readJson(required(options, "cli-args"));
    printJson({
      vk: cliArgs.vk,
      proof: cliArgs.proof,
      pub_signals: sdk.formatSorobanPubSignals(cliArgs.pub_signals),
    });
    return;
  }

  if (command === "events") {
    const data = sdk.readJson(required(options, "file"));
    printJson({
      network: data.network,
      indexedAt: data.indexedAt,
      count: data.events.length,
      events: data.events.map((event) => ({
        flow: event.flow,
        outcome: event.outcome,
        policyId: event.policyId,
        actionId: event.actionId,
        txHash: event.txHash,
        piiOnChain: event.piiOnChain,
      })),
    });
    return;
  }

  if (command === "disclosure" && subcommand === "verify") {
    const summary = sdk.readJson(required(options, "summary"));
    if (!summary.verified) {
      throw new Error("disclosure summary is not verified");
    }
    printJson({
      verified: true,
      packetHash: summary.packetHash,
      paymentTx: summary.paymentTx,
      actionId: summary.actionId,
    });
    return;
  }

  if (command === "gate" && (subcommand === "payment" || subcommand === "rwa")) {
    const contract = required(options, "contract");
    const cliArgsFile = path.normalize(required(options, "cli-args"));
    const inputFile = path.normalize(required(options, "input"));
    const network = options.network || "testnet";
    const sourceAccount = options["source-account"] || "<SOURCE_ACCOUNT>";
    const outDir = path.normalize(options["out-dir"] || path.join(".m6", "invoke", subcommand));
    console.log(
      buildStellarCommand(
        subcommand,
        contract,
        cliArgsFile,
        inputFile,
        network,
        sourceAccount,
        outDir,
      ),
    );
    return;
  }

  throw new Error(`unknown command ${options._.join(" ")}`);
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
