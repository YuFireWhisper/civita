use ark_ec::{short_weierstrass::SWCurveConfig, CurveConfig};

use crate::crypto::hash_to_curve::{iso_map::IsoMap, utils::Z};

pub mod simple_swu;

pub trait AbZero: SWCurveConfig {
    const A_PRIME: Self::BaseField;
    const B_PRIME: Self::BaseField;
}

pub trait MapToCurve: CurveConfig {
    fn map_to_curve(u: Self::BaseField) -> (Self::BaseField, Self::BaseField);
}

impl<C> MapToCurve for C
where
    C: SWCurveConfig + Z,
{
    default fn map_to_curve(u: C::BaseField) -> (C::BaseField, C::BaseField) {
        simple_swu::map_to_curve_simple_swu(u, C::COEFF_A, C::COEFF_B, C::Z)
    }
}

impl<C> MapToCurve for C
where
    C: SWCurveConfig + Z + AbZero + IsoMap,
{
    fn map_to_curve(u: C::BaseField) -> (C::BaseField, C::BaseField) {
        let (x_prime, y_prime) =
            simple_swu::map_to_curve_simple_swu(u, Self::A_PRIME, Self::B_PRIME, C::Z);
        C::iso_map(x_prime, y_prime)
    }
}
