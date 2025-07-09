use ark_ff::Field;

use crate::crypto::ec::hash_to_curve::utils::{inv0, sgn0};

/// Implements the Simplified Shallue-van de Woestijne-Ulas Method.
/// Note: The curve's coefficients A and B can't be zero.
pub fn map_to_curve_simple_swu<F: Field>(u: F, a: F, b: F, z: F) -> (F, F) {
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

    let tv1 = inv0(z.square() * u.square() * u.square() + z * u.square());

    let mut x1 = (-b / a) * (F::ONE + tv1);

    if tv1.is_zero() {
        x1 = b / (z * a);
    }

    let gx1 = x1.square() * x1 + a * x1 + b;
    let x2 = z * u.square() * x1;
    let gx2 = x2.square() * x2 + a * x2 + b;

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

    (x, y)
}
