const path = require("path");
const sdk = require("../../packages/sdk/src");

const repo = path.resolve(__dirname, "..", "..");

function mockStellarSdk({ txHash = "f".repeat(64), statuses = ["PENDING", "SUCCESS"] } = {}) {
  const calls = {
    getAccount: [],
    simulateTransaction: [],
    signXdrs: [],
    sendTransaction: [],
    getTransaction: [],
  };

  class Server {
    async getAccount(address) {
      calls.getAccount.push(address);
      return { accountId: address, sequence: "1" };
    }

    async simulateTransaction(transaction) {
      calls.simulateTransaction.push(transaction);
      return { result: "simulated" };
    }

    async sendTransaction(transaction) {
      calls.sendTransaction.push(transaction);
      return { status: "PENDING", hash: txHash };
    }

    async getTransaction(hash) {
      calls.getTransaction.push(hash);
      return { status: statuses.shift() || "SUCCESS" };
    }
  }

  class Contract {
    constructor(id) {
      this.id = id;
    }

    call(name, ...args) {
      return { contractId: this.id, name, args };
    }
  }

  class Spec {
    constructor(entries) {
      this.entries = entries;
    }

    funcArgsToScVals(name, args) {
      return [{ name, args, entries: this.entries.length }];
    }
  }

  class Transaction {
    constructor(operation) {
      this.operation = operation;
    }

    toXDR() {
      return JSON.stringify(this.operation, (_key, value) =>
        typeof value === "bigint" ? value.toString() : value,
      );
    }
  }

  class TransactionBuilder {
    constructor(account, options) {
      this.account = account;
      this.options = options;
      this.operation = null;
    }

    addOperation(operation) {
      this.operation = operation;
      return this;
    }

    setTimeout(timeout) {
      this.timeout = timeout;
      return this;
    }

    build() {
      return new Transaction({
        account: this.account,
        options: this.options,
        operation: this.operation,
        timeout: this.timeout,
      });
    }

    static fromXDR(xdr, networkPassphrase) {
      return { xdr, networkPassphrase, signed: true };
    }
  }

  return {
    calls,
    rpc: {
      Server,
      assembleTransaction(transaction) {
        return {
          build() {
            return transaction;
          },
        };
      },
    },
    contract: { Spec },
    Contract,
    TransactionBuilder,
  };
}

function mockFreighter({ signedTxXdr = "signed-xdr" } = {}) {
  const calls = [];
  return {
    calls,
    async signTransaction(xdr, options) {
      calls.push({ xdr, options });
      return { signedTxXdr };
    },
  };
}

async function runFreighterE2E({
  stellarSdk = mockStellarSdk(),
  freighterApi = mockFreighter(),
  sourceAddress = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
} = {}) {
  const paymentInput = sdk.readJson(path.join(repo, "testdata", "eligibility", "input.valid.json"));
  const paymentCliArgs = sdk.readJson(path.join(repo, "testdata", "eligibility", "cli-args.json"));
  const spec = sdk.readJson(path.join(repo, "apps", "web", "data", "gate-payment-spec.json"));
  const deployments = sdk.readJson(path.join(repo, "deployments", "testnet-hardened.json"));
  const result = await sdk.submitPaymentProof({
    stellarSdk,
    freighterApi,
    networkPassphrase: "Test SDF Network ; September 2015",
    contractId: deployments.contracts.gate_payment,
    sourceAddress,
    proof: paymentCliArgs.proof,
    publicSignals: paymentCliArgs.pub_signals,
    action: paymentInput,
    specEntries: spec.entries,
    pollIntervalMs: 0,
    pollAttempts: 2,
  });

  return { result, stellarSdk, freighterApi };
}

module.exports = {
  mockFreighter,
  mockStellarSdk,
  runFreighterE2E,
};
