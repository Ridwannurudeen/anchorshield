// One-command real-anchor run against the SDF public reference anchor (testanchor.stellar.org).
// Bootstraps ephemeral SEP-10 auth + SEP-12 customers, derives proof-bound fields, then exercises
// the SEP-38 price/quote and SEP-31 receive-create flow via sep-client. Records real anchor
// responses to services/anchor/out/sandbox-run.json (gitignored). Run from WSL (open network);
// the bash sandbox cannot reach testanchor. Nothing here uses committed secrets.
import * as SDK from "@stellar/stellar-sdk";
import * as snarkjs from "snarkjs";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const dir = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(dir, "..", "..");
const sep = require("./sep-client.js");
const BASE = "https://testanchor.stellar.org",
  HOME = "testanchor.stellar.org";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function j(url, opts, tries = 3) {
  let last;
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetch(url, {
        ...opts,
        signal: AbortSignal.timeout(20000),
      });
      const t = await r.text();
      let d;
      try {
        d = JSON.parse(t);
      } catch {
        d = t;
      }
      if (!r.ok) throw new Error(`HTTP ${r.status} ${t.slice(0, 250)}`);
      return d;
    } catch (e) {
      last = e;
      if (e.message.startsWith("HTTP")) throw e;
      await sleep(2000);
    }
  }
  throw new Error("fetch failed: " + (last?.cause?.code || last?.message));
}

const kp = SDK.Keypair.random(),
  G = kp.publicKey();
console.log("ephemeral account:", G);
await fetch(`https://friendbot.stellar.org?addr=${G}`, {
  signal: AbortSignal.timeout(20000),
}).catch(() => {});
await sleep(3000);
const ch = await j(`${BASE}/auth?account=${G}&home_domain=${HOME}`);
const tx = new SDK.Transaction(ch.transaction, ch.network_passphrase);
tx.sign(kp);
const token = (
  await j(`${BASE}/auth`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ transaction: tx.toXDR() }),
  })
).token;
console.log("SEP-10 auth: token acquired");
const putCustomer = (type) =>
  j(`${BASE}/sep12/customer`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      account: G,
      type,
      first_name: "Ada",
      last_name: "Lovelace",
      email_address: "ada@example.com",
      address: "1 Stellar Way",
      bank_account_number: "12345678",
      bank_number: "021000021",
      bank_account_type: "checking",
    }),
  });
const senderId = (await putCustomer("sep31-sender")).id,
  receiverId = (await putCustomer("sep31-receiver")).id;
console.log("SEP-12 customers:", senderId, receiverId);

const input = JSON.parse(
  fs.readFileSync(
    process.env.ANCHORSHIELD_PAYMENT_INPUT ||
      path.join(repo, "testdata/eligibility/input.valid.json"),
  ),
);
const amount = input.amount;
const { publicSignals } = await snarkjs.groth16.fullProve(
  input,
  path.join(repo, "apps/web/proving/eligibility.wasm"),
  path.join(repo, "apps/web/proving/eligibility_final.zkey"),
);
const config = {
  homeDomain: HOME,
  webAuthEndpoint: `${BASE}/auth`,
  transferServerSep31: `${BASE}/sep31`,
  anchorQuoteServer: `${BASE}/sep38`,
  token,
  sellAsset: "iso4217:USD",
  buyAsset:
    "stellar:SRT:GCDNJUBQSX7AJWLJACMJ7I4BC3Z47BQUTMHEICZLE6MU4KQBRYG5JY6B",
  receiveAssetCode: "SRT",
  senderId,
  receiverId,
  quoteExpiresAt: new Date(Date.now() + 3600e3).toISOString(),
  fundingMethod: "bank_account",
  packetHash: publicSignals[1],
  actionBinding: publicSignals[3],
};

const out = {
  schema: "anchorshield.anchor_sandbox_run.v1",
  mode: "real-anchor-sandbox",
  anchor: HOME,
  account: G,
  steps: {},
};
const price = await sep.sep38Price({
  anchorQuoteServer: config.anchorQuoteServer,
  token,
  price: {
    context: "sep31",
    sell_asset: config.sellAsset,
    buy_asset: config.buyAsset,
    sell_amount: amount,
  },
});
out.steps.sep38_price = {
  ok: true,
  price: price.price,
  total_price: price.total_price,
};
console.log("SEP-38 price:", price.price);
const quote = await sep.sep38PostQuote({
  anchorQuoteServer: config.anchorQuoteServer,
  token,
  quote: {
    context: "sep31",
    sell_asset: config.sellAsset,
    buy_asset: config.buyAsset,
    sell_amount: amount,
    expire_after: config.quoteExpiresAt,
  },
});
out.steps.sep38_quote = {
  ok: true,
  id: quote.id,
  price: quote.price,
  expires_at: quote.expires_at,
};
console.log("SEP-38 quote id:", quote.id);
try {
  const txr = await sep.sep31PostTransaction({
    transferServerSep31: config.transferServerSep31,
    token,
    transaction: sep.buildSep31Transaction({
      config,
      quote,
      payment: {
        policy_id: input.policy_id,
        amount,
        packet_hash: config.packetHash,
        action_binding: config.actionBinding,
      },
    }),
  });
  out.steps.sep31_create = { ok: true, id: txr.id };
  console.log("SEP-31 transaction id:", txr.id);
} catch (e) {
  out.steps.sep31_create = { ok: false, anchor_side_error: e.message };
  console.log("SEP-31 create blocked (anchor-side asset config):", e.message);
}
const outPath = path.join(dir, "out", "sandbox-run.json");
fs.mkdirSync(path.dirname(outPath), { recursive: true });
fs.writeFileSync(outPath, JSON.stringify(out, null, 2) + "\n");
console.log("wrote", path.relative(repo, outPath));
