use ark_ec::{AffineRepr, CurveConfig};
use ark_ff::MontFp;

use crate::crypto::hash_to_curve::utils::Z;

pub mod simple_swu;

pub trait MapToCurve<C: CurveConfig> {
    type Output: AffineRepr<Config = C>;

    fn map_to_curve(u: C::BaseField) -> Self::Output;
}

impl Z<ark_secp256k1::Config> for ark_secp256k1::Config {
    const Z: ark_secp256k1::Fq = MontFp!("-11");
}
