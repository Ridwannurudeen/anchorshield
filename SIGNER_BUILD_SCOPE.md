# Build Scope — Move enrollment root-signing to an isolated, constrained signer

**Branch:** `feat/self-serve-onboarding` (continue here — do NOT merge `main` in; `main`
carries a revert of the depth-16 work and merging it would undo this branch). Keep your
in-flight uncommitted edits; this scope adds a new service and rewires one call site.

## Why

Today `services/issuer/enrollment-store.js` → `publishCredentialRoot()` → `rootCommand()`
shells out `stellar contract invoke set_root --source $ANCHORSHIELD_STELLAR_SOURCE` directly
from inside the **internet-facing** `services/kyc-backend` process. Two problems:

1. **Bare key in the web tier.** The process that terminates public `/api/enroll` requests
   also holds (via the stellar CLI keystore) the issuer admin key. A web-tier compromise =
   key compromise = attacker can rewrite the credential root and forge eligibility.
2. **Caller dictates the root.** `publishCredentialRoot({ credentialRoot, ... })` signs
   whatever root it is handed. The signer should *derive* the root itself, not trust input.

This is NOT about adding an HSM. It is the achievable, honest improvement: a separate,
loopback-only **signer service** that (a) is the only process with key access, and (b) only
ever signs a credential root it independently recomputed from the enrollment state. A web
compromise can then at worst *trigger a republish of the legitimate root* — it cannot
exfiltrate the key and cannot push a forged root. State that limitation plainly in docs;
do not overclaim.

## Deliverables

### 1. `services/signer/signer.js` — the isolated signer service

- Dependency-free `node:http`, same style as `services/kyc-backend/server.js`. Binds
  **127.0.0.1** only, on `SIGNER_PORT` (default `3099`). **Never** proxied by nginx.
- Config via env (never commit): `SIGNER_TOKEN` (shared bearer, required to start),
  `ANCHORSHIELD_STELLAR_SOURCE` (admin key alias/identity — lives ONLY in this process's
  env), `ANCHORSHIELD_ROOT_PUBLISH_APPROVED` (must be `1` to actually broadcast; otherwise
  dry-run), optional `SIGNER_PORT`.
- One endpoint: `POST /publish-credential-root`.
  - Auth: constant-time compare of `Authorization: Bearer <SIGNER_TOKEN>`; 401 otherwise.
    Reject non-loopback `req.socket.remoteAddress` outright (defense in depth).
  - Body: `{ issuerId }` only. **Do NOT accept a root from the caller.**
  - Behavior: load the enrollment state + issuance via the SAME code the web tier uses
    (`buildEnrollmentView` from `enrollment-store.js`), recompute `credential_root`, then:
    1. Resolve the configured source to an address with `publicKeyOrIdentityAddress()`
       (export it from `publish-roots.js`) and assert it equals `deployments.admin`; reuse
       the `assertPublishIdentity` shape. 403 if it does not match.
    2. If not approved → return `{ mode: "dry-run", command, credential_root }` (no broadcast).
    3. If approved → run the `set_root` invoke via `spawnSync` (`shell:false`, arg array —
       reuse `rootCommand()` from `enrollment-store.js`, exported). On non-zero status throw
       with `code: "ROOT_PUBLISH_FAILED"`; map to 502.
  - Per-IP/token rate limit mirroring `kyc-backend` (`rateLimited` pattern) to bound cost.
- Add `GET /healthz` → `{ ok, approved, admin }`.
- Factor `createSigner({ runner, deploymentsPath, statePath, ... })` so tests inject a fake
  `runner` (no real stellar). `if (require.main === module)` boots and listens.

### 2. `services/signer/client.js` — web-tier → signer client

- Export `publishCredentialRootViaSigner({ credentialRoot, issuerId, deployments, fetchImpl })`
  matching the EXISTING `rootPublisher({ credentialRoot, issuerId, deployments })` contract
  used in `enrollment-store.js:285`, so the swap is a one-line default change.
  - Note: `credentialRoot` is still passed for parity/logging but the signer ignores it and
    recomputes; document that the signer is authoritative.
  - POST to `http://127.0.0.1:${SIGNER_PORT}/publish-credential-root` with the bearer token
    (`SIGNER_TOKEN` from env), body `{ issuerId }`. Map non-2xx to an error with
    `code: "ROOT_PUBLISH_FAILED"` so the existing kyc-backend handler
    (`server.js:434`) keeps returning 502 unchanged.

### 3. Rewire the web tier — remove key access

- `services/issuer/enrollment-store.js`: change the default `rootPublisher` for the
  **server path** to `publishCredentialRootViaSigner`. Keep `publishCredentialRoot`/
  `rootCommand` exported (the signer reuses them) but the kyc-backend must no longer be able
  to invoke stellar itself.
- `services/kyc-backend/server.js`: ensure it constructs the store with the signer-client
  publisher and **does not** read `ANCHORSHIELD_STELLAR_SOURCE`. The key alias must not be
  present in the kyc-backend's environment/systemd unit.

### 4. Tests (run green before handing back)

- `services/signer/signer.test.js`:
  - recomputes root from enrollment state and ignores any caller-supplied root;
  - 401 without/with wrong bearer; rejects non-loopback;
  - 403 when configured source ≠ deployed admin (inject fake runner returning a different
    address);
  - dry-run by default; broadcasts only when approved (assert the injected runner got the
    exact `set_root` arg array from `rootCommand`);
  - 502 mapping on non-zero invoke status.
- Update `services/kyc-backend/server.test.js` and any enrollment test to inject a mock
  signer client (no real HTTP). Assert `/api/enroll` still returns the credential payload +
  `root_publish` shape, and that a signer failure surfaces as 502.
- Add all new files to `scripts/verify.mjs` `node --check` list and the JSON/parse loop if
  any new JSON is added.

### 5. Docs

- Short `services/signer/README.md`: what it is, the threat model it does and does NOT cover
  (isolated software signer, key off the web tier, recompute-and-derive; **not** an HSM/KMS,
  no threshold/multisig), the env vars, and the production upgrade path (KMS-backed signer or
  M-of-N governance signer using the existing governance contract).
- Update `apps/web/onchain.html` (or wherever the architecture note lives) one line: root
  publishing is performed by an isolated signer, not the request handler.

## Guardrails (hard)

- **Verify-first:** read each file before editing; match existing style (arg-array spawn,
  dry-run/approved gating, runner injection, loopback bind, `logProviderError` shape).
- No new deps. No `any`/placeholders/TODOs. No secrets committed. No attribution / no
  Co-Authored-By in commits.
- **Do NOT deploy** (no VPS changes, no nginx edits, no real broadcast) — deployment is
  approval-gated and separate. Default everything to dry-run.
- **Do NOT touch `main`** and do NOT `git merge main` (revert trap).
- Run `npm run m5` (or `node scripts/verify.mjs`) + `m6` + clippy/fmt; everything green.
- Keep the change minimal: one new service dir, one default-publisher swap, test updates,
  docs. Do not refactor unrelated code.

## Acceptance criteria

1. kyc-backend process has **no** path to sign on-chain and **no** admin key in its env.
2. The signer signs only a credential root it recomputed itself; a caller-supplied root is
   ignored; identity-mismatch and unapproved states are refused.
3. Full local verify suite green; `/api/enroll` behavior unchanged from the user's POV.
4. README states the real (non-HSM) threat model honestly.

---

## Deployment (build this too — `docs/SIGNER_DEPLOY.md`)

Goal: on the production host the admin key is reachable by the **signer user only**, never by
the internet-facing kyc-backend user, and the signer port is never exposed by nginx. Mirror
the existing kyc-backend deploy convention (`docs/OPERATIONS.md:59-77`: kyc-backend on
`127.0.0.1:3092`, nginx `location /api/kyc/`, admin key imported with
`stellar keys add anchorshield-admin --secret-key`). The admin identity is
`GAJJW5XC23IRZXGY2F36JP4GDFSQ4A65FTZLWCO4EA4JKYZGHEKZJ35U`.

### Code prerequisite (do in the main build, not just docs)

The signer and the kyc-backend run as **different unix users** but must read/write the **same**
enrollment state. `createEnrollmentStore` already accepts `statePath`; wire it (and the signer)
to an env var `ANCHORSHIELD_ENROLLMENT_STATE_PATH` (default unchanged:
`services/issuer/out/enrollments.json`) so both processes can be pointed at a shared file.
kyc-backend writes it (atomic rename, already implemented); the signer only reads it.

### Honest constraints (state these in the doc; do not overclaim)

- This is an **isolated software signer on the same host** (separate unix user + scoped
  keystore), not an HSM and not a separate machine. It removes the key from the web process
  and makes forged roots impossible; it does **not** protect against host root compromise.
  True isolation = separate host / KMS / threshold — list as the upgrade path.
- The production VPS currently has **no stellar CLI installed** (verified) — the signer user
  must install it. Node is already present.
- The exact stellar keystore path is CLI-version-dependent — **confirm it on the box**
  (`stellar keys ls` as the signer user, then locate the identity file) rather than hardcoding
  a path; lock that file to `0600` owned by the signer user.

### Steps

1. **Signer unix user**, no login shell, own home:
   `useradd --system --create-home --shell /usr/sbin/nologin anchorshield-signer`.
2. **Install stellar CLI** for that user (cargo or the official installer), confirm
   `stellar --version`.
3. **Import the admin key as the signer user only** (interactive, never in a file/arg):
   `sudo -u anchorshield-signer -H stellar keys add anchorshield-admin --secret-key`.
   Confirm `sudo -u anchorshield-signer -H stellar keys address anchorshield-admin` prints
   `GAJJW5XC…35U`. Lock the keystore file `0600`, owner `anchorshield-signer` (path per the
   on-box check above). The kyc-backend user must have **no** read access.
4. **Shared enrollment state**: create `/var/lib/anchorshield`, group `anchorshield` (add both
   service users), dir `2775` (setgid) so new files inherit the group; point both units at
   `ANCHORSHIELD_ENROLLMENT_STATE_PATH=/var/lib/anchorshield/enrollments.json`. kyc-backend
   user: group-writable; signer user: read.
5. **Shared bearer token**: generate `SIGNER_TOKEN` (`openssl rand -hex 32`), put it in an
   `EnvironmentFile` readable by each unit's user, `0600`. Same value in both units.
6. **`anchorshield-signer.service`** (new systemd unit):
   - `User=anchorshield-signer`, `ExecStart=/usr/bin/node /opt/anchorshield/services/signer/signer.js`
   - `EnvironmentFile=` with `SIGNER_PORT=3099`, `SIGNER_TOKEN=…`,
     `ANCHORSHIELD_STELLAR_SOURCE=anchorshield-admin`,
     `ANCHORSHIELD_ENROLLMENT_STATE_PATH=/var/lib/anchorshield/enrollments.json`, and
     `ANCHORSHIELD_ROOT_PUBLISH_APPROVED=1` **only when** you intend live broadcast (leave
     unset/`0` for dry-run staging).
   - Hardening: `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`,
     `PrivateTmp=yes`, `ReadWritePaths=/var/lib/anchorshield`,
     `IPAddressAllow=localhost`, `IPAddressDeny=any`.
7. **Update `anchorshield-kyc.service`** (the kyc-backend unit): **remove**
   `ANCHORSHIELD_STELLAR_SOURCE`; **add** `SIGNER_PORT=3099`, `SIGNER_TOKEN=…`, and the shared
   `ANCHORSHIELD_ENROLLMENT_STATE_PATH`. This unit's user keeps **no** stellar key.
8. **nginx: no change.** Do **not** add a `/api/signer/` location. The signer stays
   loopback-only (`127.0.0.1:3099`). Confirm the existing `location /api/kyc/` → `:3092` block
   is intact.
9. **Enable + verify (staging, dry-run first):**
   - `systemctl enable --now anchorshield-signer && systemctl restart anchorshield-kyc`
   - `curl -s -H "Authorization: Bearer $SIGNER_TOKEN" 127.0.0.1:3099/healthz`
     → `{ ok:true, approved:false, admin:"GAJJW5XC…35U" }`
   - Run one real enroll through the public `/api/kyc/` path; confirm the signer logs a
     **dry-run** publish and the enrollment state updated.
   - Flip `ANCHORSHIELD_ROOT_PUBLISH_APPROVED=1` on the **signer unit only**, restart it, enroll
     again, then `npm run issuer:publish-roots -- --verify` (or the on-chain `root` getter) shows
     the credential root matches the recomputed value.
10. **Rollback**: `systemctl stop anchorshield-signer` → enrollments still append locally but
    root publish returns 502 (web tier already maps `ROOT_PUBLISH_FAILED` → 502); no key exposed.

### Deploy acceptance criteria

- `sudo -u <kyc-user> stellar keys address anchorshield-admin` **fails** (no access); the same
  command as `anchorshield-signer` succeeds.
- Signer port unreachable from the public interface; reachable only on loopback with the token.
- A staged enroll publishes the **recomputed** root (not a caller value) once approved, and is
  refused (403) if the signer identity ever resolves to anything but `GAJJW5XC…35U`.
- **No deploy is run without your explicit approval** — Codex writes the unit files + doc and
  validates them in staging/dry-run; it does not flip `*_APPROVED=1` on the live host or
  broadcast mainnet/testnet roots without sign-off.
