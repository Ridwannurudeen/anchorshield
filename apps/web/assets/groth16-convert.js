// In-browser Groth16 proof -> Soroban argument converter.
//
// Serializes a snarkjs BLS12-381 proof to the exact bytes the on-chain verifier expects, so the
// browser can submit the SAME proof it just generated and verified (no pre-converted proof pool).
// This is a verified, byte-for-byte JS port of tools/groth16-json-converter (ark serialize):
//   G1 point  -> fqBE(x) || fqBE(y)
//   G2 point  -> fqBE(x_c1) || fqBE(x_c0) || fqBE(y_c1) || fqBE(y_c0)   (Fq2 components swapped)
// where fqBE is the 48-byte big-endian encoding of the field element. Equality with the Rust
// converter is asserted in scripts/groth16-convert.test.js against a golden vector.
(function (root, factory) {
  if (typeof module !== "undefined" && module.exports) {
    module.exports = factory();
  } else {
    root.AnchorShieldConvert = factory();
  }
})(typeof self !== "undefined" ? self : this, function () {
  function fqBE(dec) {
    const hex = BigInt(dec).toString(16);
    if (hex.length > 96) {
      throw new Error("field element exceeds 48 bytes");
    }
    return hex.padStart(96, "0");
  }

  function g1(point) {
    return fqBE(point[0]) + fqBE(point[1]);
  }

  function g2(point) {
    return (
      fqBE(point[0][1]) +
      fqBE(point[0][0]) +
      fqBE(point[1][1]) +
      fqBE(point[1][0])
    );
  }

  // proof: a snarkjs groth16 proof object { pi_a, pi_b, pi_c, curve }.
  // Returns { a, b, c } as lowercase hex strings (G1 = 96 bytes, G2 = 192 bytes).
  function convertG16Proof(proof) {
    if (proof.curve && proof.curve !== "bls12381") {
      throw new Error(`expected bls12381 proof, got ${proof.curve}`);
    }
    return {
      a: g1(proof.pi_a),
      b: g2(proof.pi_b),
      c: g1(proof.pi_c),
    };
  }

  return { convertG16Proof, fqBE };
});
