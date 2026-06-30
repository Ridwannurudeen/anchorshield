# Signer Deployment Runbook

This runbook keeps the issuer admin key in a loopback-only signer process instead
of the internet-facing KYC backend. It mirrors the existing production convention:
static web through nginx, KYC on `127.0.0.1:3092`, and the signer on
`127.0.0.1:3099` with no nginx location.

Do not run these steps on the live host, enable `ANCHORSHIELD_ROOT_PUBLISH_APPROVED=1`,
or broadcast roots without explicit approval.

## Honest Isolation Boundary

This is same-host software isolation: a separate unix user owns the Stellar
identity, the web process has no key access, and the signer recomputes the root
before publishing. It blocks forged caller-supplied roots and removes the bare key
from the web tier. It does not survive host root compromise.

The upgrade path is a separate signer host, KMS-backed key policy, or
governance/threshold signing before mainnet.

## Files

- `docs/systemd/anchorshield-signer.service`
- `docs/systemd/anchorshield-kyc.service`
- `/etc/anchorshield/signer.env`
- `/etc/anchorshield/kyc.env`
- `/var/lib/anchorshield/enrollments.json`

## Users And State

Create the shared group and the signer user:

```bash
groupadd --system anchorshield
useradd --system --create-home --home-dir /var/lib/anchorshield-signer --shell /usr/sbin/nologin --gid anchorshield anchorshield-signer
usermod -aG anchorshield anchorshield-kyc
install -d -o anchorshield-kyc -g anchorshield -m 2775 /var/lib/anchorshield
install -d -o anchorshield-signer -g anchorshield -m 0700 /var/lib/anchorshield-signer
```

`ANCHORSHIELD_ENROLLMENT_STATE_PATH` must point both services at:

```text
/var/lib/anchorshield/enrollments.json
```

The KYC backend writes this file. The signer reads it and recomputes the
credential root from the same state.

## Stellar Identity

Install the Stellar CLI for `anchorshield-signer` and verify it:

```bash
sudo -u anchorshield-signer -H stellar --version
```

Import the admin key interactively as the signer user only:

```bash
sudo -u anchorshield-signer -H stellar keys add anchorshield-admin --secret-key
sudo -u anchorshield-signer -H stellar keys address anchorshield-admin
```

The address must be:

```text
GAJJW5XC23IRZXGY2F36JP4GDFSQ4A65FTZLWCO4EA4JKYZGHEKZJ35U
```

Confirm the CLI keystore path on the box with `stellar keys ls` and lock the
identity file to `0600`, owned by `anchorshield-signer`. The KYC service user
must not be able to read it.

## Environment Files

Generate one token and put the same value in both env files:

```bash
openssl rand -hex 32
install -d -o root -g root -m 0755 /etc/anchorshield
```

`/etc/anchorshield/signer.env`, owned by `anchorshield-signer:anchorshield`,
mode `0600`:

```ini
SIGNER_TOKEN=replace-with-generated-token
ANCHORSHIELD_STELLAR_SOURCE=anchorshield-admin
ANCHORSHIELD_ENROLLMENT_STATE_PATH=/var/lib/anchorshield/enrollments.json
# Leave unset or 0 for dry-run staging. Set to 1 only after explicit approval.
ANCHORSHIELD_ROOT_PUBLISH_APPROVED=0
```

`/etc/anchorshield/kyc.env`, owned by `anchorshield-kyc:anchorshield`,
mode `0600`:

```ini
SIGNER_TOKEN=replace-with-generated-token
SIGNER_PORT=3099
ANCHORSHIELD_ENROLLMENT_STATE_PATH=/var/lib/anchorshield/enrollments.json
SUMSUB_APP_TOKEN=...
SUMSUB_SECRET_KEY=...
SUMSUB_LEVEL_NAME=...
```

Do not put `ANCHORSHIELD_STELLAR_SOURCE` in the KYC env file.

## systemd

Install the checked-in unit files:

```bash
install -m 0644 docs/systemd/anchorshield-signer.service /etc/systemd/system/anchorshield-signer.service
install -m 0644 docs/systemd/anchorshield-kyc.service /etc/systemd/system/anchorshield-kyc.service
systemctl daemon-reload
systemctl enable --now anchorshield-signer
systemctl restart anchorshield-kyc
```

The signer service binds to `127.0.0.1:3099`. Do not add an nginx
`/api/signer/` location.

The optional `IPAddressDeny=any` hardening line is documented in the signer unit
but commented out: enabling it without an explicit Soroban RPC allowlist blocks
approved root broadcasts. It is safe for dry-run-only staging, but live publishing
needs outbound Stellar RPC access.

## Dry-Run Verification

```bash
curl -s -H "Authorization: Bearer $SIGNER_TOKEN" http://127.0.0.1:3099/healthz
```

Expected shape:

```json
{ "ok": true, "approved": false, "admin": "GAJJW5XC23IRZXGY2F36JP4GDFSQ4A65FTZLWCO4EA4JKYZGHEKZJ35U" }
```

Run a real enrollment through `/api/kyc/`. Confirm:

- KYC state updates in `/var/lib/anchorshield/enrollments.json`.
- Signer logs show a dry-run root publish.
- `sudo -u anchorshield-kyc -H stellar keys address anchorshield-admin` fails.
- `sudo -u anchorshield-signer -H stellar keys address anchorshield-admin` succeeds.
- Port `3099` is reachable only from loopback with the bearer token.

## Approved Publish

Only after explicit approval, set `ANCHORSHIELD_ROOT_PUBLISH_APPROVED=1` in
`/etc/anchorshield/signer.env` and restart the signer:

```bash
systemctl restart anchorshield-signer
```

Run one enrollment, then verify the on-chain root:

```bash
npm run issuer:publish-roots -- --verify
```

If the signer identity resolves to anything other than the deployed admin, the
publish endpoint returns `403` and does not invoke Stellar.

## Rollback

```bash
systemctl stop anchorshield-signer
```

Enrollments still append locally, but root publishing returns `502` through the
web tier and the admin key remains outside the KYC backend.
