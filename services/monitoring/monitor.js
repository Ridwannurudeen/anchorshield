const fs = require("fs");
const path = require("path");

const repo = path.resolve(__dirname, "..", "..");

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function normalizeEvents(input) {
  if (!input) return [];
  if (Array.isArray(input)) return input;
  if (Array.isArray(input.events)) return input.events;
  throw new Error("monitoring input must contain an events array");
}

function alert(id, severity, kind, message, event = {}) {
  return {
    id,
    severity,
    kind,
    message,
    flow: event.flow || null,
    txHash: event.txHash || event.tx_hash || null,
    contractId: event.contractId || event.contract_id || null,
    at: event.at || null,
  };
}

function rootEventInfo(event) {
  const type = event.type || event.eventName || "";
  if (/CredentialRootSet|credential_root_set/i.test(type)) {
    return { kind: "credential_root_changed", rootName: "credential_root" };
  }
  if (/SanctionsRootSet|sanctions_root_set/i.test(type)) {
    return { kind: "sanctions_root_changed", rootName: "sanctions_root" };
  }
  if (/RevocationRootSet|revocation_root_set/i.test(type)) {
    return { kind: "revocation_root_changed", rootName: "revocation_root" };
  }
  return null;
}

function eventRoot(event) {
  return String(event.root || event.credential_root || event.sanctions_root || event.revocation_root || "");
}

function buildAlerts({
  events = [],
  issuance,
  now = new Date(),
  maxRootAgeHours = 24,
} = {}) {
  const alerts = [];
  const seenNullifiers = new Map();
  const normalized = normalizeEvents(events);

  for (const event of normalized) {
    const rootInfo = rootEventInfo(event);
    if (rootInfo) {
      const root = eventRoot(event);
      const expected = issuance?.roots?.[rootInfo.rootName] || null;
      alerts.push(
        alert(
          `${rootInfo.kind}:${event.txHash || event.tx_hash || root}`,
          expected && root !== expected ? "critical" : "info",
          rootInfo.kind,
          expected && root !== expected
            ? `${rootInfo.rootName} differs from current issuer output`
            : `${rootInfo.rootName} updated`,
          event,
        ),
      );
    }

    const nullifier = event.nullifier && String(event.nullifier);
    if (nullifier) {
      if (seenNullifiers.has(nullifier)) {
        alerts.push(
          alert(
            `nullifier_replay:${nullifier}:${event.txHash || event.tx_hash || "unknown"}`,
            "critical",
            "nullifier_replay",
            "nullifier appeared in more than one proof event",
            event,
          ),
        );
      }
      seenNullifiers.set(nullifier, event);
    }

    const failed =
      /InvalidProof|invalid_proof|failed_proof/i.test(event.type || event.eventName || "") ||
      /invalid_proof|failed/i.test(event.outcome || event.reason || "");
    if (failed) {
      alerts.push(
        alert(
          `invalid_proof:${event.txHash || event.tx_hash || alerts.length}`,
          "critical",
          "invalid_proof",
          "proof verification failed or was rejected",
          event,
        ),
      );
    }
  }

  if (issuance?.generated_at) {
    const generatedAt = new Date(issuance.generated_at);
    const ageMs = now.getTime() - generatedAt.getTime();
    const maxAgeMs = maxRootAgeHours * 60 * 60 * 1000;
    if (ageMs > maxAgeMs) {
      alerts.push({
        id: `root_stale:${issuance.generated_at}`,
        severity: "warning",
        kind: "root_stale",
        message: "issuer roots are older than the configured freshness window",
        generated_at: issuance.generated_at,
        age_hours: Number((ageMs / 60 / 60 / 1000).toFixed(3)),
        max_age_hours: maxRootAgeHours,
      });
    }
  }

  return alerts;
}

async function emitAlerts(alerts, { webhookUrl, fetchImpl = fetch, log = console.log } = {}) {
  for (const item of alerts) {
    log(JSON.stringify(item));
  }
  if (webhookUrl && alerts.length > 0) {
    const response = await fetchImpl(webhookUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ alerts }),
    });
    if (!response.ok) {
      throw new Error(`alert webhook failed: HTTP ${response.status}`);
    }
  }
  return { emitted: alerts.length, webhook: Boolean(webhookUrl) };
}

async function runMonitor({
  eventsPath = path.join(repo, "services", "indexer", "compliance-events.json"),
  issuancePath = path.join(repo, "services", "issuer", "out", "issuance.json"),
  outPath = path.join(repo, "services", "monitoring", "out", "alerts.json"),
  webhookUrl = process.env.ANCHORSHIELD_ALERT_WEBHOOK_URL,
  maxRootAgeHours = Number(process.env.ANCHORSHIELD_ROOT_MAX_AGE_HOURS || 24),
} = {}) {
  const events = fs.existsSync(eventsPath) ? readJson(eventsPath) : { events: [] };
  const issuance = fs.existsSync(issuancePath) ? readJson(issuancePath) : null;
  const alerts = buildAlerts({
    events,
    issuance,
    maxRootAgeHours,
  });
  const result = {
    schema: "anchorshield.monitoring.v1",
    generated_at: new Date().toISOString(),
    events: normalizeEvents(events).length,
    alerts,
  };
  writeJson(outPath, result);
  await emitAlerts(alerts, { webhookUrl });
  return result;
}

if (require.main === module) {
  runMonitor()
    .then((result) => {
      console.log(JSON.stringify(result, null, 2));
      if (result.alerts.some((item) => item.severity === "critical")) {
        process.exit(1);
      }
    })
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
}

module.exports = {
  buildAlerts,
  emitAlerts,
  normalizeEvents,
  runMonitor,
};
