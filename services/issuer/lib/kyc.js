// KYC provider adapter for the AnchorShield issuer.
//
// Provider-agnostic seam: a provider returns verified attributes for an applicant, which the
// issuer maps onto the credential fields the circuit expects (kyc_passed, country, age, ...).
// A Sumsub sandbox implementation is included (grounded in the standard Sumsub REST + HMAC auth).
// Configure via env (never commit secrets):
//   SUMSUB_APP_TOKEN, SUMSUB_SECRET_KEY  (sandbox token carries the `sbx:` prefix)
//   SUMSUB_BASE_URL    (default https://api.sumsub.com)
//   SUMSUB_LEVEL_NAME  (the verification level configured in the Sumsub dashboard)
// No keys configured -> createKycProvider() returns null and the issuer falls back to the roster.

const crypto = require("crypto");

// ISO 3166 alpha-3 -> numeric, matching the numeric `country` the circuit/policy use.
const COUNTRY_ALPHA3_TO_NUMERIC = {
  NGA: 566,
  USA: 840,
  GBR: 826,
  ARE: 784,
  SGP: 702,
  HKG: 344,
  ZAF: 710,
  KEN: 404,
};

function alpha3ToNumeric(alpha3) {
  const code = COUNTRY_ALPHA3_TO_NUMERIC[String(alpha3 || "").toUpperCase()];
  if (!code) {
    throw new Error(
      `unmapped country ${alpha3}; add it to COUNTRY_ALPHA3_TO_NUMERIC`,
    );
  }
  return code;
}

function ageFromDob(dob) {
  const birth = new Date(dob);
  if (Number.isNaN(birth.getTime())) {
    throw new Error(`invalid date of birth: ${dob}`);
  }
  const now = new Date();
  let age = now.getFullYear() - birth.getFullYear();
  const m = now.getMonth() - birth.getMonth();
  if (m < 0 || (m === 0 && now.getDate() < birth.getDate())) {
    age -= 1;
  }
  return age;
}

function createSumsubProvider({ appToken, secretKey, baseUrl, levelName }) {
  function sign(method, uri, body, ts) {
    return crypto
      .createHmac("sha256", secretKey)
      .update(ts + method + uri + (body || ""))
      .digest("hex");
  }

  async function request(method, uri, body) {
    const ts = Math.floor(Date.now() / 1000);
    const bodyString = body ? JSON.stringify(body) : "";
    const res = await fetch(`${baseUrl}${uri}`, {
      method,
      headers: {
        "X-App-Token": appToken,
        "X-App-Access-Sig": sign(method, uri, bodyString, ts),
        "X-App-Access-Ts": String(ts),
        ...(body ? { "Content-Type": "application/json" } : {}),
      },
      body: body ? bodyString : undefined,
    });
    const text = await res.text();
    if (!res.ok) {
      throw new Error(
        `Sumsub ${method} ${uri} -> HTTP ${res.status} ${text.slice(0, 250)}`,
      );
    }
    return text ? JSON.parse(text) : {};
  }

  async function getApplicant(externalUserId) {
    return request(
      "GET",
      `/resources/applicants/-;externalUserId=${encodeURIComponent(externalUserId)}/one`,
    );
  }

  // Returns verified credential attributes for a GREEN applicant, or null if not approved.
  async function verifiedCredential(externalUserId) {
    const applicant = await getApplicant(externalUserId);
    const answer = applicant?.review?.reviewResult?.reviewAnswer;
    if (answer !== "GREEN") {
      return null;
    }
    // `info` = data recognized from the verified documents (authoritative); `fixedInfo` =
    // applicant-submitted (used only as a fallback). Validate field shapes (country alpha-3,
    // dob) against a real sandbox applicant response before relying on this in production.
    const verified = applicant.info || {};
    const submitted = applicant.fixedInfo || {};
    const info = {
      country: verified.country || submitted.country,
      dob: verified.dob || submitted.dob,
    };
    if (!info.country || !info.dob) {
      throw new Error(
        `applicant ${externalUserId} GREEN but missing country/dob in verified info`,
      );
    }
    return {
      kyc_passed: 1,
      country: alpha3ToNumeric(info.country),
      age: ageFromDob(info.dob),
      applicant_id: applicant.id,
      review_answer: answer,
    };
  }

  return { provider: "sumsub", levelName, getApplicant, verifiedCredential };
}

function createKycProvider(env = process.env) {
  const appToken = env.SUMSUB_APP_TOKEN;
  const secretKey = env.SUMSUB_SECRET_KEY;
  if (!appToken || !secretKey) {
    return null;
  }
  return createSumsubProvider({
    appToken,
    secretKey,
    baseUrl: env.SUMSUB_BASE_URL || "https://api.sumsub.com",
    levelName: env.SUMSUB_LEVEL_NAME || "anchorshield-basic-kyc",
  });
}

module.exports = {
  createKycProvider,
  createSumsubProvider,
  alpha3ToNumeric,
  ageFromDob,
  COUNTRY_ALPHA3_TO_NUMERIC,
};
