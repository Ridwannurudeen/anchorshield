# Publish Checklist

Publishing remains user-gated. The packages are prepared at `0.1.0` but remain `private: true`.

## Packages

- `packages/sdk` -> `@anchorshield/sdk`
- `packages/cli` -> `anchorshield`

## Before Removing `private`

- Choose and add the final license file, then update package `license` fields away from `UNLICENSED`.
- Confirm package names and scopes with `npm view @anchorshield/sdk` and `npm view anchorshield`.
- Run `npm run m6:verify`.
- Run `npm run publish:preflight`; it must pass before any publish.
- Run `npm pack --dry-run` in both `packages/sdk` and `packages/cli`.
- Confirm no generated proofs, secrets, `.env`, ceremony private artifacts, or deployment signer material are included.
- Get explicit user approval for the actual publish.

## Publish Commands After Approval

```bash
cd packages/sdk
npm publish --access public

cd ../cli
npm publish --access public
```
