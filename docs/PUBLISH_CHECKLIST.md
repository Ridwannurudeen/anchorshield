# Publish Checklist

Publishing remains user-gated. The packages are public-ready at `0.1.0`
(`private: false`, Apache-2.0 metadata), and the next publish must bump versions
if `@anchorshield/sdk@0.1.0` or `anchorshield@0.1.0` already exists on npm.

## Packages

- `packages/sdk` -> `@anchorshield/sdk`
- `packages/cli` -> `anchorshield`

## Before Any Future Publish

- Confirm package names and currently published versions with `npm view @anchorshield/sdk versions --json` and `npm view anchorshield versions --json`.
- Bump both package versions before publishing if the current version already exists.
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
