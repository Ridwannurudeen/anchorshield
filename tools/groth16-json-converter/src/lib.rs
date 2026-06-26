use ark_bls12_381::{Fq, Fq2, G1Affine as ArkG1Affine, G2Affine as ArkG2Affine};
use ark_serialize::CanonicalSerialize;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::fs;
use std::path::Path;
use std::str::FromStr;

#[derive(Debug)]
pub enum ConvertError {
    Io(std::io::Error),
    Json(serde_json::Error),
    InvalidCurve(String),
    InvalidPoint(&'static str),
    InvalidField(String),
}

impl Display for ConvertError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::Json(err) => write!(f, "JSON error: {err}"),
            Self::InvalidCurve(curve) => write!(f, "unsupported proof curve: {curve}"),
            Self::InvalidPoint(name) => write!(f, "invalid point shape: {name}"),
            Self::InvalidField(value) => write!(f, "invalid BLS12-381 field value: {value}"),
        }
    }
}

impl std::error::Error for ConvertError {}

impl From<std::io::Error> for ConvertError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<serde_json::Error> for ConvertError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err)
    }
}

#[derive(Debug, Deserialize)]
struct SnarkProof {
    pi_a: Vec<String>,
    pi_b: Vec<Vec<String>>,
    pi_c: Vec<String>,
    curve: String,
}

#[derive(Debug, Deserialize)]
struct SnarkVerificationKey {
    vk_alpha_1: Vec<String>,
    vk_beta_2: Vec<Vec<String>>,
    vk_gamma_2: Vec<Vec<String>>,
    vk_delta_2: Vec<Vec<String>>,
    #[serde(rename = "IC")]
    ic: Vec<Vec<String>>,
    curve: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct CliProof {
    pub a: String,
    pub b: String,
    pub c: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct CliVerificationKey {
    pub alpha: String,
    pub beta: String,
    pub gamma: String,
    pub delta: String,
    pub ic: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct CliU256 {
    pub u256: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct CliArgs {
    pub vk: CliVerificationKey,
    pub proof: CliProof,
    pub pub_signals: Vec<CliU256>,
}

pub fn convert_files(
    proof_path: &Path,
    vk_path: &Path,
    public_path: &Path,
) -> Result<CliArgs, ConvertError> {
    let proof: SnarkProof = serde_json::from_str(&fs::read_to_string(proof_path)?)?;
    let vk: SnarkVerificationKey = serde_json::from_str(&fs::read_to_string(vk_path)?)?;
    let pub_signals: Vec<String> = serde_json::from_str(&fs::read_to_string(public_path)?)?;
    convert(proof, vk, pub_signals)
}

fn convert(
    proof: SnarkProof,
    vk: SnarkVerificationKey,
    pub_signals: Vec<String>,
) -> Result<CliArgs, ConvertError> {
    require_bls12381(&proof.curve)?;
    require_bls12381(&vk.curve)?;

    Ok(CliArgs {
        vk: CliVerificationKey {
            alpha: g1_hex("vk_alpha_1", &vk.vk_alpha_1)?,
            beta: g2_hex("vk_beta_2", &vk.vk_beta_2)?,
            gamma: g2_hex("vk_gamma_2", &vk.vk_gamma_2)?,
            delta: g2_hex("vk_delta_2", &vk.vk_delta_2)?,
            ic: vk
                .ic
                .iter()
                .map(|point| g1_hex("IC", point))
                .collect::<Result<Vec<_>, _>>()?,
        },
        proof: CliProof {
            a: g1_hex("pi_a", &proof.pi_a)?,
            b: g2_hex("pi_b", &proof.pi_b)?,
            c: g1_hex("pi_c", &proof.pi_c)?,
        },
        pub_signals: pub_signals
            .into_iter()
            .map(|signal| CliU256 { u256: signal })
            .collect(),
    })
}

fn require_bls12381(curve: &str) -> Result<(), ConvertError> {
    if curve == "bls12381" {
        Ok(())
    } else {
        Err(ConvertError::InvalidCurve(curve.to_owned()))
    }
}

fn fq(value: &str) -> Result<Fq, ConvertError> {
    Fq::from_str(value).map_err(|_| ConvertError::InvalidField(value.to_owned()))
}

fn g1_hex(name: &'static str, coords: &[String]) -> Result<String, ConvertError> {
    if coords.len() < 2 {
        return Err(ConvertError::InvalidPoint(name));
    }

    let point = ArkG1Affine::new(fq(&coords[0])?, fq(&coords[1])?);
    let mut buf = Vec::new();
    point
        .serialize_uncompressed(&mut buf)
        .map_err(|_| ConvertError::InvalidPoint(name))?;
    Ok(hex_encode(&buf))
}

fn g2_hex(name: &'static str, coords: &[Vec<String>]) -> Result<String, ConvertError> {
    if coords.len() < 2 || coords[0].len() < 2 || coords[1].len() < 2 {
        return Err(ConvertError::InvalidPoint(name));
    }

    let x = Fq2::new(fq(&coords[0][0])?, fq(&coords[0][1])?);
    let y = Fq2::new(fq(&coords[1][0])?, fq(&coords[1][1])?);
    let point = ArkG2Affine::new(x, y);
    let mut buf = Vec::new();
    point
        .serialize_uncompressed(&mut buf)
        .map_err(|_| ConvertError::InvalidPoint(name))?;
    Ok(hex_encode(&buf))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
