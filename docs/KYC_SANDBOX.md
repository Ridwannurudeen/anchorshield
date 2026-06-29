# KYC Sandbox (Sumsub)

The credential source can be backed by a real KYC provider. The issuer maps a verified Sumsub
applicant onto the credential fields (`services/issuer/lib/kyc.js`). No keys configured ⇒ the
issuer falls back to the synthetic roster, so this is fully opt-in.

## What you set up in the Sumsub dashboard (sandbox mode)

1. **App token + secret.** Dev Space → App Tokens → create a token in **Sandbox**. The sandbox
   token carries the `sbx:` prefix. Copy the App Token and the Secret Key.
2. **A verification level** that captures an **identity document** (so country + date of birth are
   recognized). Name it `anchorshield-basic-kyc` (or reuse an existing level and set
   `SUMSUB_LEVEL_NAME`).
3. **A GREEN test applicant** under that level: create an applicant with an `externalUserId` you
   choose, complete it with a document carrying a country + DOB, and get it to **GREEN** (the
   sandbox lets you approve/simulate it). Note the `externalUserId`.

## What you put on disk (never committed)

Create `services/issuer/.env` (gitignored):

```
SUMSUB_APP_TOKEN=sbx:...
SUMSUB_SECRET_KEY=...
SUMSUB_LEVEL_NAME=anchorshield-basic-kyc
```

## Validate the live mapping

Run from WSL (open network; the bash sandbox cannot reach `api.sumsub.com`):

```bash
node services/issuer/kyc-validate.js <externalUserId>
```

It prints the applicant's review answer, the **raw** `info`/`fixedInfo` field shapes, and the
mapped credential — so the field mapping (`info.country` alpha-3 → ISO numeric, `info.dob` → age)
is confirmed against a real response, not assumed. If a country is unmapped, add it to
`COUNTRY_ALPHA3_TO_NUMERIC` in `services/issuer/lib/kyc.js`.

## Notes

- Only document-verified `info` is trusted for the credential; applicant-submitted `fixedInfo` is
  a fallback only.
- The applicant's `country` must match the gate policy's `allowed_country` for the end-to-end
  proof to pass (the demo policy pins one country — make the test applicant match it).
- Issuer-policy fields (`investor_type`, `tx_limit`, `issued_at`, `expires_at`) are issuer-set, not
  taken from KYC.
