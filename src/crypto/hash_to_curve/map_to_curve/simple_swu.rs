use ark_ec::{
    short_weierstrass::{Affine, SWCurveConfig},
    AffineRepr,
};
use ark_ff::{Field, Zero};

use crate::crypto::hash_to_curve::{
    iso_map::IsoMap,
    map_to_curve::{MapToCurve, Z},
    utils::{inv0, sgn0},
};

pub trait AbZero {}

/// Implements the Simplified Shallue-van de Woestijne-Ulas Method.
/// Note: The curve's coefficients A and B can't be zero.
fn map_to_curve_simple_swu<C: SWCurveConfig + Z<C>>(u: C::BaseField) -> Affine<C> {
    // The pseudocode in RFC 9380
    // ```
    // 1. tv1 = inv0(Z^2 * u^4 + Z * u^2)
    // 2.  x1 = (-B / A) * (1 + tv1)
    // 3.  If tv1 == 0, set x1 = B / (Z * A)
    // 4. gx1 = x1^3 + A * x1 + B
    // 5.  x2 = Z * u^2 * x1
    // 6. gx2 = x2^3 + A * x2 + B
    // 7.  If is_square(gx1), set x = x1 and y = sqrt(gx1)
    // 8.  Else set x = x2 and y = sqrt(gx2)
    // 9.  If sgn0(u) != sgn0(y), set y = -y
    // 10. return (x, y)
    // ```

    let tv1 = inv0(C::Z.square() * u.square() * u.square() + C::Z * u.square());
    let mut x1 = (-C::COEFF_B / C::COEFF_A) * (C::BaseField::ONE + tv1);

    if tv1.is_zero() {
        x1 = C::COEFF_B / (C::Z * C::COEFF_A);
    }

    let gx1 = x1.square() * x1 + C::COEFF_A * x1 + C::COEFF_B;
    let x2 = C::Z * u.square() * x1;
    let gx2 = x2.square() * x2 + C::COEFF_A * x2 + C::COEFF_B;

    let x;
    let mut y;
    if gx1.legendre().is_qr() {
        x = x1;
        y = gx1.sqrt().unwrap();
    } else {
        x = x2;
        y = gx2.sqrt().unwrap();
    }

    if sgn0(&u) != sgn0(&y) {
        y = -y;
    }

    Affine::<C>::new(x, y)
}

impl<C: SWCurveConfig + Z<C>> MapToCurve<C> for C {
    fn map_to_curve(u: C::BaseField) -> impl AffineRepr<Config = C> {
        map_to_curve_simple_swu::<C>(u)
    }
}

impl<C> MapToCurve<C> for C
where
    C: SWCurveConfig + AbZero + Z<C>,
    Affine<C>: IsoMap,
{
    fn map_to_curve(u: C::BaseField) -> impl AffineRepr<Config = C> {
        let point = map_to_curve_simple_swu::<C>(u);
        point.iso_map()
    }
}

impl AbZero for ark_secp256k1::FqConfig {}
