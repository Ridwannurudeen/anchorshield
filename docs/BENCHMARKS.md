# Benchmarks

## Testnet Fees

| Milestone | Contract | Operation | Tx | Final fee |
| --- | --- | --- | --- | --- |
| M0 | `CBM5Q5IKAMEIO7J7AOROHNK3S46LGVUJU2HE5DHKK53X7DLVG7AICRCL` | official multiplier proof verification | `2542702391f5858715615013e53d05ea3837055d7cc83bb965cc1bbe41f35565` | `39644` stroops |
| M1 | `CD4FWZ5HH6H4XDSWVVQCZ354LWHJVCN6TV72UEHTLOMKQPKJAGHU5WGE` | eligibility proof verify + mock payment | `e17e8fda2496824569d3497cddc845fd7721c560822de5e6912984e9ab2bde7d` | `268639` stroops |
| M2 | `CC6D22NXA4B6YRA4KANN5A44DBC3QEKT4AUPU2VMHP3RHJIIYNGNWP3T` | eligibility proof verify + mock RWA transfer | `c1cb42fd7e5bd666cc2daf5a8368f7d1e6865aba296278b21bf5d428931e66f7` | `238157` stroops |

## Circuit Sizes

| Circuit | Curve | Constraints | Public inputs | Public outputs |
| --- | --- | ---: | ---: | ---: |
| `eligibility.circom` | BLS12-381 | `15866` | `13` | `4` |
