use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_ff::{BigInteger, Field, PrimeField, Zero};

/// Implements the Shallue-van de Woestijne map to curve method
/// Following IETF spec 6.6.1 for Weierstrass curves
pub fn map_to_curve<C: SWCurveConfig>(u: C::BaseField) -> Affine<C> {
    // Precompute the constant Z
    let z = find_z_svdw::<C>(1);
    let g_z = g::<C>(z);

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
        * (C::BaseField::from(3) * z.square() + C::BaseField::from(4) * C::COEFF_A))
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
        / (C::BaseField::from(3) * z.square() + C::BaseField::from(4) * C::COEFF_A);

    // IETF spec 6.6.1 step 9: x1 = -Z / 2 - tv5
    let x1 = -z / C::BaseField::from(2) - tv5;

    // IETF spec 6.6.1 step 10: x2 = -Z / 2 + tv5
    let x2 = -z / C::BaseField::from(2) + tv5;

    // IETF spec 6.6.1 step 11: x3 = Z + tv6 * (tv2^2 * tv3)^2
    let x3 = z + tv6 * (tv2.square() * tv3).square();

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

/// Implements the sgn0 function as defined in IETF spec 4.1
/// Returns 0 or 1 based on the "sign" of the field element
fn sgn0<F: Field>(x: &F) -> i8 {
    // IETF spec 4.1 step 1: sign = 0
    let mut sign = 0i8;

    // IETF spec 4.1 step 2: zero = 1 (true)
    let mut zero = true;

    // IETF spec 4.1 steps 3-7: iterate through all elements
    for x_i in x.to_base_prime_field_elements() {
        // IETF spec 4.1 step 4: sign_i = x_i mod 2
        let sign_i = if x_i.into_bigint().is_odd() { 1i8 } else { 0i8 };

        // IETF spec 4.1 step 5: zero_i = x_i == 0
        let zero_i = x_i.is_zero();

        // IETF spec 4.1 step 6: sign = sign OR (zero AND sign_i)
        // Avoid short-circuit logic operations
        sign |= (zero as i8) & sign_i;

        // IETF spec 4.1 step 7: zero = zero AND zero_i
        zero = zero && zero_i;
    }

    // IETF spec 4.1 step 8: return sign
    sign
}

/// Finds a suitable Z value for the Shallue-van de Woestijne mapping
/// Following IETF spec H.1 algorithm
fn find_z_svdw<C: SWCurveConfig>(init_ctr: u64) -> C::BaseField {
    // Define the h function as per IETF spec H.1
    let h = |z: C::BaseField| -> Option<C::BaseField> {
        let gz = g::<C>(z);
        if gz.is_zero() {
            return None;
        }
        let z_square = z.square();
        let numerator =
            -(C::BaseField::from(3u32) * z_square + C::BaseField::from(4u32) * C::COEFF_A);
        let denominator = C::BaseField::from(4u32) * gz;
        Some(numerator * inv0(denominator))
    };

    let mut ctr = init_ctr;
    loop {
        for z_cand in [C::BaseField::from(ctr), -C::BaseField::from(ctr)] {
            // IETF spec H.1 Criterion 1: g(Z) != 0 in F
            let gz = g::<C>(z_cand);
            if gz.is_zero() {
                continue;
            }

            let hz = match h(z_cand) {
                Some(hz) => hz,
                None => continue,
            };

            // IETF spec H.1 Criterion 2: -(3 * Z^2 + 4 * A) / (4 * g(Z)) != 0 in F
            if hz.is_zero() {
                continue;
            }

            // IETF spec H.1 Criterion 3: -(3 * Z^2 + 4 * A) / (4 * g(Z)) is square in F
            if !hz.legendre().is_qr() {
                continue;
            }

            // IETF spec H.1 Criterion 4: At least one of g(Z) and g(-Z/2) is square in F
            let gz_is_square = gz.legendre().is_qr();

            let neg_z_half = -z_cand * inv0(C::BaseField::from(2u32));
            let g_neg_z_half = g::<C>(neg_z_half);
            let g_neg_z_half_is_square = g_neg_z_half.legendre().is_qr();

            if gz_is_square || g_neg_z_half_is_square {
                return z_cand;
            }
        }

        ctr += 1;
    }
}

/// Calculates the Weierstrass curve equation g(x) = x^3 + A*x + B
fn g<C: SWCurveConfig>(x: C::BaseField) -> C::BaseField {
    x.square() * x + C::COEFF_A * x + C::COEFF_B
}

/// Implementation of inv0 function - returns 0 when input is 0, otherwise returns 1/x
fn inv0<F: Field>(x: F) -> F {
    x.inverse().unwrap_or(F::zero())
}

#[cfg(test)]
mod tests {
    use ark_ec::CurveConfig;

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
