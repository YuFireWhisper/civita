use ark_ff::MontFp;
use ark_secp256r1::Fr;

use crate::crypto::ec::{serialize_size::SerializeSize, vrf::Config};

const COFACTOR_SCALAR: Fr = MontFp!("1");

impl SerializeSize for ark_secp256r1::Config {
    const AFFINE_SIZE: usize = 33;
    const SCALAR_SIZE: usize = 32;
}

impl Config for ark_secp256r1::Config {
    const COFACTOR_SCALAR: Self::ScalarField = COFACTOR_SCALAR;
}
