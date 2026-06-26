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

    assert_eq!(converted.pub_signals.len(), 17);
    assert_eq!(converted.vk.ic.len(), 18);
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
        "3b2584866b5ab1196ee080e8ec3a4f3a26c585515b0222911757e4cf81e2bea9"
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

    assert_eq!(converted.pub_signals.len(), 17);
    assert_eq!(converted.vk.ic.len(), 18);
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
        "af0770901a2219fb24dc0a8224b12bd5ba638f0014ed8d5cf54e67d6a8b43171"
    );
}
