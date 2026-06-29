// Unit tests for the KYC adapter. Sumsub network calls are mocked, so this verifies the
// adapter LOGIC (auth-less). Live field-shape correctness against a real sandbox applicant
// response is a separate step that requires SUMSUB_APP_TOKEN/SECRET + a GREEN test applicant.

const assert = require("assert");
const {
  createKycProvider,
  createSumsubProvider,
  alpha3ToNumeric,
  ageFromDob,
} = require("./kyc");

const checks = [];
function check(name, fn) {
  checks.push([name, fn]);
}

function withMockFetch(applicant, fn) {
  const original = global.fetch;
  const calls = [];
  global.fetch = async (url, opts) => {
    calls.push({ url, opts });
    return {
      ok: true,
      status: 200,
      text: async () => JSON.stringify(applicant),
    };
  };
  return Promise.resolve(fn(calls)).finally(() => {
    global.fetch = original;
  });
}

const KEYS = {
  appToken: "sbx:tok",
  secretKey: "sec",
  baseUrl: "https://api.sumsub.com",
  levelName: "anchorshield-basic-kyc",
};

check("no keys -> provider is null (issuer falls back to roster)", () => {
  assert.strictEqual(createKycProvider({}), null);
});

check("keys present -> sumsub provider", () => {
  const p = createKycProvider({
    SUMSUB_APP_TOKEN: "sbx:t",
    SUMSUB_SECRET_KEY: "s",
  });
  assert.strictEqual(p.provider, "sumsub");
});

check("auth headers + signed request shape", () =>
  withMockFetch(
    { review: { reviewResult: { reviewAnswer: "RED" } } },
    async (calls) => {
      await createSumsubProvider(KEYS).getApplicant("ext-1");
      const h = calls[0].opts.headers;
      assert.strictEqual(h["X-App-Token"], "sbx:tok");
      assert.ok(/^[0-9a-f]{64}$/.test(h["X-App-Access-Sig"]), "hex sha256 sig");
      assert.ok(h["X-App-Access-Ts"], "timestamp present");
      assert.match(
        calls[0].url,
        /\/resources\/applicants\/-;externalUserId=ext-1\/one$/,
      );
    },
  ),
);

check("non-GREEN applicant -> null (no credential issued)", () =>
  withMockFetch(
    { review: { reviewResult: { reviewAnswer: "RED" } } },
    async () => {
      assert.strictEqual(
        await createSumsubProvider(KEYS).verifiedCredential("ext-2"),
        null,
      );
    },
  ),
);

check("GREEN applicant -> mapped credential from verified info", () =>
  withMockFetch(
    {
      id: "app-1",
      review: { reviewResult: { reviewAnswer: "GREEN" } },
      info: { country: "NGA", dob: "1990-01-01" },
    },
    async () => {
      const c = await createSumsubProvider(KEYS).verifiedCredential("ext-3");
      assert.strictEqual(c.kyc_passed, 1);
      assert.strictEqual(c.country, 566);
      assert.ok(c.age >= 30);
      assert.strictEqual(c.applicant_id, "app-1");
    },
  ),
);

check("prefers document-verified info over applicant-submitted fixedInfo", () =>
  withMockFetch(
    {
      review: { reviewResult: { reviewAnswer: "GREEN" } },
      info: { country: "USA", dob: "1985-06-15" },
      fixedInfo: { country: "NGA", dob: "1990-01-01" },
    },
    async () => {
      const c = await createSumsubProvider(KEYS).verifiedCredential("ext-4");
      assert.strictEqual(c.country, 840);
    },
  ),
);

check("GREEN but unmapped country -> throws (no silent wrong code)", () =>
  withMockFetch(
    {
      review: { reviewResult: { reviewAnswer: "GREEN" } },
      info: { country: "FRA", dob: "1990-01-01" },
    },
    async () => {
      await assert.rejects(
        () => createSumsubProvider(KEYS).verifiedCredential("ext-5"),
        /unmapped country/,
      );
    },
  ),
);

check("pure: alpha3ToNumeric + ageFromDob", () => {
  assert.strictEqual(alpha3ToNumeric("usa"), 840);
  assert.throws(() => alpha3ToNumeric("ZZZ"), /unmapped/);
  assert.strictEqual(typeof ageFromDob("2000-01-01"), "number");
  assert.throws(() => ageFromDob("not-a-date"), /invalid date/);
});

(async () => {
  let passed = 0;
  for (const [name, fn] of checks) {
    try {
      await fn();
      console.log(`ok - ${name}`);
      passed += 1;
    } catch (e) {
      console.log(`FAIL - ${name}: ${e.message}`);
      process.exitCode = 1;
    }
  }
  console.log(`\n${passed}/${checks.length} checks passed`);
})();
