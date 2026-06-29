# Browser Wallet E2E

The automated harness is `services/wallet-e2e/freighter-harness.test.js`. It injects a Freighter-compatible signer and a mocked Stellar RPC/SDK surface, then drives the same SDK `submitPaymentProof` path used by the browser payment flow:

```bash
npm run wallet:e2e
```

Manual Freighter testnet run:

1. Import or create a funded Freighter testnet account.
2. Serve the web app with `npm run m3:web`.
3. Open `http://127.0.0.1:4173`, connect Freighter, generate the payment proof, then submit.
4. Confirm Freighter shows `gate_payment.verify_and_pay` on Stellar testnet.
5. Record the submitted tx hash and confirm a second submission of the same proof is rejected by the nullifier registry.
