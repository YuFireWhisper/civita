use ark_ec::CurveConfig;
use ark_ff::{BigInteger, Field, PrimeField, Zero};

pub trait Z: CurveConfig {
    const Z: Self::BaseField;
}

pub trait L: CurveConfig {
    const L: usize;
}

/// Implements the sgn0 function as defined in IETF spec 4.1
/// Returns 0 or 1 based on the "sign" of the field element
pub fn sgn0<F: Field>(x: &F) -> i8 {
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

/// Implementation of inv0 function - returns 0 when input is 0, otherwise returns 1/x
pub fn inv0<F: Field>(x: F) -> F {
    x.inverse().unwrap_or(F::zero())
}
