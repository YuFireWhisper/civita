use ark_ec::{AffineRepr, CurveConfig};
use ark_ff::MontFp;

pub mod simple_swu;
pub mod sw;

pub trait MapToCurve<C: CurveConfig> {
    fn map_to_curve(u: C::BaseField) -> impl AffineRepr<Config = C>;
}

trait Z<C: CurveConfig> {
    const Z: C::BaseField;
}

impl Z<ark_secp256k1::Config> for ark_secp256k1::Config {
    const Z: ark_secp256k1::Fq = MontFp!("-11");
}
