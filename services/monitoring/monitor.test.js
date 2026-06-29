const assert = require("assert");
const { buildAlerts, emitAlerts } = require("./monitor");

async function main() {
  const issuance = {
    generated_at: "2026-06-27T00:00:00.000Z",
    roots: {
      credential_root: "111",
      sanctions_root: "222",
      revocation_root: "333",
    },
  };
  const events = {
    events: [
      {
        type: "CredentialRootSet",
        txHash: "root-a",
        root: "111",
      },
      {
        type: "SanctionsRootSet",
        txHash: "root-b",
        root: "999",
      },
      {
        type: "PaymentApproved",
        txHash: "ok-a",
        nullifier: "n-1",
      },
      {
        type: "PaymentApproved",
        txHash: "replay-a",
        nullifier: "n-1",
      },
      {
        type: "InvalidProof",
        txHash: "bad-proof",
        reason: "invalid_proof",
      },
    ],
  };

  const alerts = buildAlerts({
    events,
    issuance,
    now: new Date("2026-06-28T02:00:00Z"),
    maxRootAgeHours: 24,
  });
  assert.ok(alerts.some((alert) => alert.kind === "sanctions_root_changed" && alert.severity === "critical"));
  assert.ok(alerts.some((alert) => alert.kind === "nullifier_replay"));
  assert.ok(alerts.some((alert) => alert.kind === "invalid_proof"));
  assert.ok(alerts.some((alert) => alert.kind === "root_stale"));

  const posts = [];
  const emitted = await emitAlerts(alerts, {
    webhookUrl: "https://alerts.example.test/anchorshield",
    log: () => {},
    fetchImpl: async (url, options) => {
      posts.push({ url, body: JSON.parse(options.body) });
      return { ok: true };
    },
  });
  assert.strictEqual(emitted.emitted, alerts.length);
  assert.strictEqual(posts.length, 1);
  assert.strictEqual(posts[0].body.alerts.length, alerts.length);
  console.log("monitoring tests passed");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
