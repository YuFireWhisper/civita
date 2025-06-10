use ark_ec::AffineRepr;
use ark_ff::PrimeField;

use crate::crypto::traits::hasher::Hasher;

pub fn generate_challenge<P: AffineRepr, H: Hasher>(
    suite_string: &[u8],
    points: [P; 5],
    c_len: usize,
) -> P::ScalarField {
    const DOMAIN_SEPARATOR_FRONT: u8 = 0x02;
    const DOMAIN_SEPARATOR_BACK: u8 = 0x00;

    let mut str =
        Vec::with_capacity(suite_string.len() + 1 + points[0].compressed_size() * points.len() + 1);

    str.extend_from_slice(suite_string);
    str.push(DOMAIN_SEPARATOR_FRONT);

    for p in points.iter() {
        p.serialize_compressed(&mut str)
            .expect("Failed to serialize point");
    }

    str.push(DOMAIN_SEPARATOR_BACK);

    let c_str = H::hash(&str);

    P::ScalarField::from_be_bytes_mod_order(&c_str[..c_len.min(c_str.len())])
}
