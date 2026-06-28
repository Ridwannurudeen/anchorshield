const assert = require("assert");
const {
  sep10Challenge,
  sep10Token,
  sep31Info,
  sep31PostTransaction,
  sep31GetTransaction,
  sep38Price,
  sep38PostQuote,
  buildSep31Transaction,
} = require("./sep-client");

function installFetch(routes) {
  const calls = [];
  global.fetch = async (url, options = {}) => {
    const href = String(url);
    const method = options.method || "GET";
    calls.push({ href, method, options });
    const route = routes.find(
      (candidate) => candidate.method === method && candidate.match.test(href),
    );
    if (!route) {
      return {
        ok: false,
        status: 404,
        statusText: "Not Found",
        text: async () =>
          JSON.stringify({ error: `no mock for ${method} ${href}` }),
      };
    }
    return {
      ok: true,
      status: 200,
      statusText: "OK",
      text: async () => JSON.stringify(route.body),
    };
  };
  return calls;
}

async function main() {
  const calls = installFetch([
    {
      method: "GET",
      match: /^https:\/\/anchor\.example\/auth\?/,
      body: {
        transaction: "challenge-xdr",
        network_passphrase: "Test SDF Network ; September 2015",
      },
    },
    {
      method: "POST",
      match: /^https:\/\/anchor\.example\/auth$/,
      body: { token: "sep10-token" },
    },
    {
      method: "GET",
      match: /^https:\/\/anchor\.example\/sep31\/info$/,
      body: { receive: { native: { enabled: true } } },
    },
    {
      method: "POST",
      match: /^https:\/\/anchor\.example\/sep31\/transactions$/,
      body: { id: "tx-123", status: "pending_sender" },
    },
    {
      method: "GET",
      match: /^https:\/\/anchor\.example\/sep31\/transactions\?id=tx-123$/,
      body: { transaction: { id: "tx-123", status: "completed" } },
    },
    {
      method: "GET",
      match: /^https:\/\/anchor\.example\/sep38\/price\?/,
      body: { price: "1.00", total_price: "1.00" },
    },
    {
      method: "POST",
      match: /^https:\/\/anchor\.example\/sep38\/quote$/,
      body: { id: "quote-123", price: "1.00" },
    },
  ]);

  const challenge = await sep10Challenge({
    webAuthEndpoint: "https://anchor.example/auth",
    account: "GABC",
    homeDomain: "anchor.example",
  });
  assert.strictEqual(challenge.transaction, "challenge-xdr");

  const token = await sep10Token({
    webAuthEndpoint: "https://anchor.example/auth",
    transaction: "signed-xdr",
  });
  assert.strictEqual(token.token, "sep10-token");

  const info = await sep31Info({
    transferServerSep31: "https://anchor.example/sep31",
    token: token.token,
  });
  assert.strictEqual(info.receive.native.enabled, true);

  const price = await sep38Price({
    anchorQuoteServer: "https://anchor.example/sep38",
    token: token.token,
    price: {
      sell_asset: "iso4217:USD",
      buy_asset: "stellar:native",
      sell_amount: "250",
    },
  });
  assert.strictEqual(price.price, "1.00");

  const quote = await sep38PostQuote({
    anchorQuoteServer: "https://anchor.example/sep38",
    token: token.token,
    quote: {
      sell_asset: "iso4217:USD",
      buy_asset: "stellar:native",
      sell_amount: "250",
    },
  });
  assert.strictEqual(quote.id, "quote-123");

  const transactionBody = buildSep31Transaction({
    config: {
      receiveAssetCode: "native",
      senderId: "sender-1",
      receiverId: "receiver-1",
    },
    quote,
    payment: {
      policy_id: "202",
      amount: "250",
      packet_hash: "packet",
      action_binding: "action",
    },
  });
  assert.strictEqual(transactionBody.fields.transaction.quote_id, "quote-123");
  assert.strictEqual(
    transactionBody.fields.transaction.anchorshield_policy_id,
    "202",
  );
  assert.strictEqual(
    transactionBody.fields.transaction.anchorshield_packet_hash,
    "packet",
  );
  assert.strictEqual(
    transactionBody.fields.transaction.anchorshield_action_binding,
    "action",
  );

  const transaction = await sep31PostTransaction({
    transferServerSep31: "https://anchor.example/sep31",
    token: token.token,
    transaction: transactionBody,
  });
  assert.strictEqual(transaction.id, "tx-123");

  const fetched = await sep31GetTransaction({
    transferServerSep31: "https://anchor.example/sep31",
    token: token.token,
    id: "tx-123",
  });
  assert.strictEqual(fetched.transaction.status, "completed");

  const postCalls = calls.filter((call) => call.method === "POST");
  assert.deepStrictEqual(
    postCalls.map((call) => call.options.headers.Authorization),
    [undefined, "Bearer sep10-token", "Bearer sep10-token"],
  );

  console.log("anchor SEP client test OK");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
