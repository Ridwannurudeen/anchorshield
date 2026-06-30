# Benchmarks

Latest capture: `docs/benchmarks/latest.json` generated on 2026-06-30.

## Proof Latency

| Runtime | Flow | Input | Prove | Local verify |
| --- | --- | --- | ---: | ---: |
| Node.js snarkjs CLI | payment | `testdata/eligibility/input.valid.json` | `2064ms` | `435ms` |
| Node.js snarkjs CLI | RWA | `testdata/rwa/input.valid.json` | `1574ms` | `434ms` |
| Browser proof console | payment | in-browser onboarding witness | not recaptured | included in app timer |

Browser measurement source: rerun `npm run m3:web`, complete onboarding, generate a payment proof in `/console.html`, then rerun `node scripts/benchmarks.mjs --browser-ms=<ms>`.

## Testnet Fees

| Milestone | Contract | Operation | Tx | Final fee |
| --- | --- | --- | --- | --- |
| M0 | `CBM5Q5IKAMEIO7J7AOROHNK3S46LGVUJU2HE5DHKK53X7DLVG7AICRCL` | official multiplier proof verification | `2542702391f5858715615013e53d05ea3837055d7cc83bb965cc1bbe41f35565` | `39644` stroops |
| M1 | `CD4FWZ5HH6H4XDSWVVQCZ354LWHJVCN6TV72UEHTLOMKQPKJAGHU5WGE` | eligibility proof verify + mock payment | `e17e8fda2496824569d3497cddc845fd7721c560822de5e6912984e9ab2bde7d` | `268639` stroops |
| M2 | `CC6D22NXA4B6YRA4KANN5A44DBC3QEKT4AUPU2VMHP3RHJIIYNGNWP3T` | eligibility proof verify + mock RWA transfer | `c1cb42fd7e5bd666cc2daf5a8368f7d1e6865aba296278b21bf5d428931e66f7` | `238157` stroops |
| Hardened payment | `CB5DKGBSBPARDD64E4BRJVTLOWL76OZAQRAIJOJX5RT6Y42K54NTYJKS` | proof-gated SAC transfer | `fa40b339f576e53b4cf0e15f24a8f7ad2c97d12887e367b2697b6471110d82a4` | `193416` stroops |
| Hardened RWA | `CBVZ56BAOVOMNSGNT7PZYOOXLHZQA6RDPMZ23RT5PTWRHY5AQDOHDS4H` | `attest_for_mint` authorization | `080082f293a7281d4ae547898fdf67b92da7a2e6391c378c971f95ccb89f7e28` | `639490` stroops |
| Hardened RWA | `CDGAQDKZV4B4VQZUNHD6E6OY4L66WUPRTVKINSPMSON3JSFLR7ILXKKI` | OZ token mint with compliance adapter | `114c58d94c8a6f312919ac974311d9a05a010edd59f9f38ab6631512f453d607` | `1332553` stroops |

## Circuit Sizes

| Circuit | Curve | Constraints | Public inputs | Public outputs |
| --- | --- | ---: | ---: | ---: |
| `eligibility.circom` | BLS12-381 | `56110` | `15` | `4` |
