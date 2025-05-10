use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_ff::Field;

use crate::crypto::hash_to_curve::{
    map_to_curve::Z,
    utils::{inv0, sgn0},
};

/// Implements the Shallue-van de Woestijne map to curve method.
/// Note: Has higher performance cost, so prefer specialized implementations when available.
pub fn map_to_curve<C: SWCurveConfig + Z<C>>(u: C::BaseField) -> Affine<C> {
    // Precompute the constant Z
    let g_z = g::<C>(C::Z);

    // IETF spec 6.6.1 step 1: tv1 = u^2 * g(Z)
    let tv1 = u.square() * g_z;

    // IETF spec 6.6.1 step 2: tv2 = 1 + tv1
    let tv2 = C::BaseField::ONE + tv1;

    // IETF spec 6.6.1 step 3: tv1 = 1 - tv1
    let tv1 = C::BaseField::ONE - tv1;

    // IETF spec 6.6.1 step 4: tv3 = inv0(tv1 * tv2)
    let tv3 = inv0(tv1 * tv2);

    // IETF spec 6.6.1 step 5: tv4 = sqrt(-g(Z) * (3 * Z^2 + 4 * A))
    let mut tv4 = (-(g_z)
        * (C::BaseField::from(3) * C::Z.square() + C::BaseField::from(4) * C::COEFF_A))
        .sqrt()
        .unwrap();

    // IETF spec 6.6.1 step 6: If sgn0(tv4) == 1, set tv4 = -tv4
    if sgn0(&tv4) == 1 {
        tv4 = -tv4;
    }

    // IETF spec 6.6.1 step 7: tv5 = u * tv1 * tv3 * tv4
    let tv5 = u * tv1 * tv3 * tv4;

    // IETF spec 6.6.1 step 8: tv6 = -4 * g(Z) / (3 * Z^2 + 4 * A)
    let tv6 = -(C::BaseField::from(4) * g_z)
        / (C::BaseField::from(3) * C::Z.square() + C::BaseField::from(4) * C::COEFF_A);

    // IETF spec 6.6.1 step 9: x1 = -Z / 2 - tv5
    let x1 = -C::Z / C::BaseField::from(2) - tv5;

    // IETF spec 6.6.1 step 10: x2 = -Z / 2 + tv5
    let x2 = -C::Z / C::BaseField::from(2) + tv5;

    // IETF spec 6.6.1 step 11: x3 = Z + tv6 * (tv2^2 * tv3)^2
    let x3 = C::Z + tv6 * (tv2.square() * tv3).square();

    // IETF spec 6.6.1 steps 12-14: Choose valid x coordinate and y value
    let x;
    let mut y;
    if g::<C>(x1).legendre().is_qr() {
        // IETF spec 6.6.1 step 12: is_square(g(x1))
        x = x1;
        y = g::<C>(x1).sqrt().unwrap();
    } else if g::<C>(x2).legendre().is_qr() {
        // IETF spec 6.6.1 step 13: is_square(g(x2))
        x = x2;
        y = g::<C>(x2).sqrt().unwrap();
    } else {
        // IETF spec 6.6.1 step 14: use x3
        x = x3;
        y = g::<C>(x3).sqrt().unwrap();
    }

    // IETF spec 6.6.1 step 15: If sgn0(u) != sgn0(y), set y = -y
    if sgn0(&u) != sgn0(&y) {
        y = -y;
    }

    // IETF spec 6.6.1 step 16: return (x, y)
    Affine::<C>::new(x, y)
}

/// Calculates the Weierstrass curve equation g(x) = x^3 + A*x + B
fn g<C: SWCurveConfig>(x: C::BaseField) -> C::BaseField {
    x.square() * x + C::COEFF_A * x + C::COEFF_B
}

#[cfg(test)]
mod tests {
    use ark_ec::CurveConfig;
    use ark_ff::Zero;

    use super::*;

    fn create_test_point<C: SWCurveConfig>(x: u64) -> C::BaseField {
        C::BaseField::from(x)
    }

    #[test]
    fn map_to_curve_returns_valid_point() {
        let u = create_test_point::<ark_secp256k1::Config>(123);
        let point = map_to_curve::<ark_secp256k1::Config>(u);

        let x3 = point.x.square() * point.x;
        let ax = ark_secp256k1::Config::COEFF_A * point.x;
        let rhs = x3 + ax + ark_secp256k1::Config::COEFF_B;
        let lhs = point.y.square();

        assert_eq!(lhs, rhs);
    }

    #[test]
    fn map_to_curve_with_edge_values() {
        let zero = <ark_secp256k1::Config as CurveConfig>::BaseField::zero();
        let one = <ark_secp256k1::Config as CurveConfig>::BaseField::ONE;

        let point_from_zero = map_to_curve::<ark_secp256k1::Config>(zero);
        let point_from_one = map_to_curve::<ark_secp256k1::Config>(one);

        let verify_on_curve = |point: &Affine<ark_secp256k1::Config>| {
            let x3 = point.x.square() * point.x;
            let ax = ark_secp256k1::Config::COEFF_A * point.x;
            let rhs = x3 + ax + ark_secp256k1::Config::COEFF_B;
            let lhs = point.y.square();
            lhs == rhs
        };

        assert!(verify_on_curve(&point_from_zero));
        assert!(verify_on_curve(&point_from_one));
    }
}
