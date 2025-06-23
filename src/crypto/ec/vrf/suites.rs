use ark_ff::MontFp;
use ark_secp256r1::Fr;

use crate::crypto::ec::vrf::Cofactor;

const COFACTOR_SCALAR: Fr = MontFp!("1");

impl Cofactor for ark_secp256r1::Fr {
    const COFACTOR_SCALAR: Self = COFACTOR_SCALAR;
}
