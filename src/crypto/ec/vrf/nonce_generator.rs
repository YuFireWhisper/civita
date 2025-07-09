use ark_ff::{BigInteger, PrimeField};

use crate::crypto::traits::hasher::Hasher;

pub fn generate_nonce<H: Hasher, F: PrimeField>(private_key: F, msg: &[u8]) -> F {
    let h1 = H::hash(msg);

    let mut v = vec![0x01u8; H::BLOCK_SIZE_IN_BYTES];
    let mut k = vec![0u8; H::BLOCK_SIZE_IN_BYTES];

    let x_bytes = private_key.into_bigint().to_bytes_be();
    let h1_bits = F::from_be_bytes_mod_order(h1.digest())
        .into_bigint()
        .to_bytes_be();

    let build_data = |v: &[u8], separator: u8, x: &[u8], h: &[u8]| -> Vec<u8> {
        let mut data = Vec::with_capacity(v.len() + 1 + x.len() + h.len());
        data.extend_from_slice(v);
        data.push(separator);
        data.extend_from_slice(x);
        data.extend_from_slice(h);
        data
    };

    k = hmac::<H>(&k, &build_data(&v, 0x00, &x_bytes, &h1_bits));
    v = hmac::<H>(&k, &v);

    k = hmac::<H>(&k, &build_data(&v, 0x01, &x_bytes, &h1_bits));
    v = hmac::<H>(&k, &v);

    let modulus_bit_size = F::MODULUS_BIT_SIZE as usize;
    let required_bytes = modulus_bit_size.div_ceil(8);

    loop {
        let mut t = Vec::with_capacity(required_bytes);

        while t.len() < required_bytes {
            v = hmac::<H>(&k, &v);
            t.extend_from_slice(&v);
        }

        let candidate_k = F::from_be_bytes_mod_order(&t);

        if !candidate_k.is_zero() && candidate_k.into_bigint() < F::MODULUS {
            return candidate_k;
        }

        let data = [&v[..], &[0x00u8]].concat();
        k = hmac::<H>(&k, &data);
        v = hmac::<H>(&k, &v);
    }
}

fn hmac<H: Hasher>(key: &[u8], message: &[u8]) -> Vec<u8> {
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5C;

    let mut padded_key = vec![0u8; H::BLOCK_SIZE_IN_BYTES];

    if key.len() > H::BLOCK_SIZE_IN_BYTES {
        let hash = H::hash(key).to_bytes();
        padded_key[..hash.len()].copy_from_slice(&hash);
    } else {
        padded_key[..key.len()].copy_from_slice(key);
    }

    let inner_key: Vec<u8> = padded_key.iter().map(|&b| b ^ IPAD).collect();
    let outer_key: Vec<u8> = padded_key.iter().map(|&b| b ^ OPAD).collect();

    let mut inner_input = inner_key;
    inner_input.extend_from_slice(message);
    let inner_hash = H::hash(&inner_input);

    let mut outer_input = outer_key;
    outer_input.extend_from_slice(inner_hash.digest());
    H::hash(&outer_input).to_bytes()
}
