use ark_ec::models::short_weierstrass::SWCurveConfig;
use ark_ff::MontFp;
use ark_secp256r1::Fq;

use crate::crypto::ec::{
    base_config::BaseConfig,
    hash_to_curve::{
        expand_message::Xmd,
        map_to_curve::{simple_swu, MapToCurve},
        Config,
    },
};

#[allow(unused_imports)]
use crate::crypto::ec::suite_implements::concat_str_slices;

const Z: Fq = MontFp!("-10");

#[allow(dead_code)]
const CRATE_NAME: &str = "civita-"; // Len: 7

#[allow(dead_code)]
const VERSION: &str = "v1-"; // Len: 3

#[allow(dead_code)]
const SUITE_ID: &str = "secp256r1_XMD:SHA-256_SSWU_RO_"; // Len: 30

impl MapToCurve<Fq> for ark_secp256r1::Config {
    fn map_to_curve(u: Fq) -> (Fq, Fq) {
        simple_swu::map_to_curve_simple_swu(u, Self::COEFF_A, Self::COEFF_B, Z)
    }
}

impl BaseConfig for ark_secp256r1::Config {
    type Hasher = sha2::Sha256;
}

impl Config for ark_secp256r1::Config {
    const ACTUAL_A: Self::BaseField = Self::COEFF_A;
    const ACTUAL_B: Self::BaseField = Self::COEFF_B;

    const L: usize = 48;
    const Z: Self::BaseField = Z;

    #[cfg(not(test))]
    const DST: &'static [u8] = &concat_str_slices::<40>(CRATE_NAME, VERSION, SUITE_ID);

    #[cfg(test)]
    const DST: &'static [u8] = b"ECVRF_P256_XMD:SHA-256_SSWU_NU_";

    type ExpandMessage = Xmd;
}
