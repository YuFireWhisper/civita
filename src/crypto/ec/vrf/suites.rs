use ark_ff::MontFp;
use ark_secp256r1::Fr;

use crate::crypto::ec::vrf::Config;

const COFACTOR_SCALAR: Fr = MontFp!("1");

impl Config for ark_secp256r1::Config {
    const COFACTOR_SCALAR: Self::ScalarField = COFACTOR_SCALAR;
    const AFFINE_SIZE: usize = 33;
    const SCALAR_SIZE: usize = 32;
}
