// Verifies the in-browser converter matches the Rust converter (tools/groth16-json-converter)
// byte-for-byte on a real proof golden vector. If this passes, browser-submitted proofs are
// on-chain-valid (the Rust converter's output is the format the deployed verifier accepts).
const assert = require("assert");
const { convertG16Proof } = require("./groth16-convert");
const vector = require("./testdata/groth16-convert-vector.json");

const out = convertG16Proof(vector.proof);
assert.strictEqual(out.a, vector.expected.a, "G1 a mismatch");
assert.strictEqual(out.b, vector.expected.b, "G2 b mismatch");
assert.strictEqual(out.c, vector.expected.c, "G1 c mismatch");
assert.throws(() => convertG16Proof({ curve: "bn128", pi_a: [], pi_b: [], pi_c: [] }), /bls12381/);
console.log("ok - groth16-convert matches Rust converter byte-for-byte (a/b/c)");
