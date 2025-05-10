use ark_ec::{
    short_weierstrass::{self, SWCurveConfig},
    AffineRepr, CurveConfig,
};

use crate::crypto::hash_to_curve::{map_to_curve::MapToCurve, utils::AbZero};

mod expand_message_xmd;
mod hash_to_field;
mod iso_map;
mod map_to_curve;
mod utils;

pub trait HashToCurve<C: CurveConfig + MapToCurve<C>> {
    type Output: AffineRepr<Config = C>;

    fn hash_to_curve(msg: impl AsRef<[u8]>) -> Self::Output;
}

impl<C> HashToCurve<C> for C
where
    C: SWCurveConfig + MapToCurve<C, Output = short_weierstrass::Affine<C>>,
{
    type Output = short_weierstrass::Affine<C>;

    fn hash_to_curve(msg: impl AsRef<[u8]>) -> Self::Output {
        let u = hash_to_field::hash_to_field::<C::BaseField>(msg);
        let p = C::map_to_curve(u);
        p.mul_by_cofactor()
    }
}

impl AbZero for ark_secp256k1::Config {
    fn is_ab_zero() -> bool {
        true
    }
}
