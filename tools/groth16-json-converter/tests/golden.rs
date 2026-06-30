use groth16_json_converter::convert_files;
use sha2::{Digest, Sha256};
use std::path::Path;

#[test]
fn converts_official_stellar_groth16_fixture() {
    let converted = convert_files(
        Path::new("../../testdata/groth16/proof.json"),
        Path::new("../../testdata/groth16/verification_key.json"),
        Path::new("../../testdata/groth16/public.json"),
    )
    .unwrap();

    assert_eq!(converted.pub_signals.len(), 1);
    assert_eq!(converted.pub_signals[0].u256, "33");
    assert_eq!(converted.proof.a.len(), 96 * 2);
    assert_eq!(converted.proof.b.len(), 192 * 2);
    assert_eq!(converted.proof.c.len(), 96 * 2);
    assert_eq!(converted.vk.alpha.len(), 96 * 2);
    assert_eq!(converted.vk.beta.len(), 192 * 2);
    assert_eq!(converted.vk.gamma.len(), 192 * 2);
    assert_eq!(converted.vk.delta.len(), 192 * 2);
    assert_eq!(converted.vk.ic.len(), 2);
    assert!(converted.vk.ic.iter().all(|point| point.len() == 96 * 2));

    let json = serde_json::to_vec_pretty(&converted).unwrap();
    let hash = Sha256::digest(json);
    assert_eq!(
        format!("{hash:x}"),
        "a57d642e700621f02e83c57ea662886fb808162212468c259b4b8e140afc2c1b"
    );
}

#[test]
fn converts_m1_eligibility_fixture() {
    let converted = convert_files(
        Path::new("../../testdata/eligibility/proof.json"),
        Path::new("../../testdata/eligibility/verification_key.json"),
        Path::new("../../testdata/eligibility/public.json"),
    )
    .unwrap();

    assert_eq!(converted.pub_signals.len(), 19);
    assert_eq!(converted.vk.ic.len(), 20);
    assert_eq!(converted.pub_signals[13].u256, "250");
    assert_eq!(converted.pub_signals[15].u256, "424242");
    assert_eq!(converted.proof.a.len(), 96 * 2);
    assert_eq!(converted.proof.b.len(), 192 * 2);
    assert_eq!(converted.proof.c.len(), 96 * 2);
    assert!(converted.vk.ic.iter().all(|point| point.len() == 96 * 2));

    let json = serde_json::to_vec_pretty(&converted).unwrap();
    let hash = Sha256::digest(json);
    assert_eq!(
        format!("{hash:x}"),
        "ddb4699bff07f067eefdb7f1b6e4b78d9a34fe4a6ac35f31e6cc19691d780565"
    );
}

#[test]
fn converts_m2_rwa_fixture() {
    let converted = convert_files(
        Path::new("../../testdata/rwa/proof.json"),
        Path::new("../../testdata/rwa/verification_key.json"),
        Path::new("../../testdata/rwa/public.json"),
    )
    .unwrap();

    assert_eq!(converted.pub_signals.len(), 19);
    assert_eq!(converted.vk.ic.len(), 20);
    assert_eq!(converted.pub_signals[11].u256, "1");
    assert_eq!(converted.pub_signals[13].u256, "100");
    assert_eq!(converted.pub_signals[15].u256, "515151");
    assert_eq!(converted.proof.a.len(), 96 * 2);
    assert_eq!(converted.proof.b.len(), 192 * 2);
    assert_eq!(converted.proof.c.len(), 96 * 2);
    assert!(converted.vk.ic.iter().all(|point| point.len() == 96 * 2));

    let json = serde_json::to_vec_pretty(&converted).unwrap();
    let hash = Sha256::digest(json);
    assert_eq!(
        format!("{hash:x}"),
        "50760454712cdd3ebbe9c62012d36083c3bd8ff934028fd9edf1f9ed25d8f8ad"
    );
}
