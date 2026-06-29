# Benchmarks

Latest capture: `docs/benchmarks/latest.json` generated on 2026-06-28.

## Proof Latency

| Runtime | Flow | Input | Prove | Local verify |
| --- | --- | --- | ---: | ---: |
| Node.js snarkjs CLI | payment | `apps/web/data/payment-input.json` | `2040ms` | `597ms` |
| Node.js snarkjs CLI | RWA | `apps/web/data/rwa-input.json` | `2003ms` | `581ms` |
| Browser proof console | payment | `apps/web/data/payment-input.json` | `9467ms` | included in app timer |

Browser measurement source: local `npm run m3:web`, `/console.html`, "Run payment proof"; status `verified`.

## Testnet Fees

| Milestone | Contract | Operation | Tx | Final fee |
| --- | --- | --- | --- | --- |
| M0 | `CBM5Q5IKAMEIO7J7AOROHNK3S46LGVUJU2HE5DHKK53X7DLVG7AICRCL` | official multiplier proof verification | `2542702391f5858715615013e53d05ea3837055d7cc83bb965cc1bbe41f35565` | `39644` stroops |
| M1 | `CD4FWZ5HH6H4XDSWVVQCZ354LWHJVCN6TV72UEHTLOMKQPKJAGHU5WGE` | eligibility proof verify + mock payment | `e17e8fda2496824569d3497cddc845fd7721c560822de5e6912984e9ab2bde7d` | `268639` stroops |
| M2 | `CC6D22NXA4B6YRA4KANN5A44DBC3QEKT4AUPU2VMHP3RHJIIYNGNWP3T` | eligibility proof verify + mock RWA transfer | `c1cb42fd7e5bd666cc2daf5a8368f7d1e6865aba296278b21bf5d428931e66f7` | `238157` stroops |
| Hardened payment | `CCS7UJWD6OP2DGKEGLUCI55SROUC4A3XJ3G4QDQN35HYV3CNT47F5U3R` | proof-gated SAC transfer | `6fea602fdb2eaf59426271ce17fac7dbc9ed6a04331b5eef34bb4e33f746b0ae` | `186400` stroops |
| Hardened RWA | `CD647AFZSYWVVMBZXNMBIGCADL5FAUDJQDMHJTMVBW5NIGMZOFJKHOB7` | `attest_for_mint` authorization | `fc4175698c3a0f8a499f3ce32dd8357169842f6492e291811976bc5fe95123f2` | `600175` stroops |
| Hardened RWA | `CBYALFSEIXBLBM23IS4EQMVJXQZYGZNGMDI6NAV3TR7U2JESKIPRHGXT` | OZ token mint with compliance adapter | `fca63abfc08dfaf43b4164d876fbde49e4c5c5171bf332a5c92512cbe1d883b3` | `1235536` stroops |

## Circuit Sizes

| Circuit | Curve | Constraints | Public inputs | Public outputs |
| --- | --- | ---: | ---: | ---: |
| `eligibility.circom` | BLS12-381 | `15866` | `13` | `4` |
