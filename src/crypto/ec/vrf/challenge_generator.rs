use ark_ec::AffineRepr;
use ark_ff::PrimeField;

use crate::crypto::{error::*, traits::hasher::Hasher};

pub fn generate_challenge<P: AffineRepr, H: Hasher>(points: [P; 5]) -> Result<P::ScalarField> {
    const DOMAIN_SEPARATOR_FRONT: u8 = 0x02;
    const DOMAIN_SEPARATOR_BACK: u8 = 0x00;

    let q_len_in_bytes = P::ScalarField::MODULUS_BIT_SIZE.div_ceil(8);
    let c_len = q_len_in_bytes.div_ceil(2) as usize;

    let mut str = Vec::with_capacity(1 + points[0].compressed_size() * points.len() + 1);

    str.push(DOMAIN_SEPARATOR_FRONT);

    for p in points.iter() {
        p.serialize_compressed(&mut str)?;
    }

    str.push(DOMAIN_SEPARATOR_BACK);

    let c_str = H::hash(&str);

    Ok(P::ScalarField::from_be_bytes_mod_order(
        &c_str.digest()[..c_len.min(c_str.size() as usize)],
    ))
}
