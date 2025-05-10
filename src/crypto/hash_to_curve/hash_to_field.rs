use ark_ff::{Field, PrimeField};

use crate::crypto::{
    hash_to_curve::expand_message_xmd::expand_message_xmd,
    types::{CipherSuite, Dst},
};

// IETF Step: Security parameter k = 128 bits
const K: usize = 128;

/// Implementation of hash_to_field as defined in IETF specification section 5.2
/// This function hashes a byte string into one element of a field F
/// Optimized version that always returns a single field element (count=1)
pub fn hash_to_field<F>(msg: impl AsRef<[u8]>) -> F
where
    F: Field,
{
    // IETF Step 0 (preparation): Calculate L = ceil((ceil(log2(p)) + k) / 8)
    let l = (ceil_log2(F::characteristic()) + K) / 8;

    // IETF Step 1: Calculate len_in_bytes = m * L (for count=1)
    // where m is the extension degree of F
    let len_in_bytes = F::extension_degree() as usize * l;

    // IETF Step 2: Generate uniform bytes using expand_message
    let dst = Dst::new(CipherSuite::from_field::<F>().expect("Unsupported field type"));
    let uniform_bytes = expand_message_xmd(msg.as_ref(), dst, len_in_bytes);

    // For count=1, we only need one field element
    let mut e: Vec<F::BasePrimeField> = Vec::with_capacity(F::extension_degree() as usize);

    // IETF Step 4: For each component of the extension field
    for j in 0..F::extension_degree() {
        // IETF Step 5: Calculate element offset (simplified for count=1)
        let elm_offset = l * j as usize;

        // IETF Step 6: Extract substring of uniform bytes
        let tv = &uniform_bytes[elm_offset..elm_offset + l];

        // IETF Step 7: Convert to integer and reduce modulo p
        let e_j = F::BasePrimeField::from_be_bytes_mod_order(tv);
        e.push(e_j);
    }

    // IETF Step 8: Construct field element from components
    F::from_base_prime_field_elems(e).expect("e.len != F::extension_degree()")
}

/// Calculate ceiling of log2 of a prime represented as a big integer
/// This implements part of the L calculation: ceil(log2(p))
fn ceil_log2(p: &'static [u64]) -> usize {
    for (i, &limb) in p.iter().enumerate().rev() {
        if limb != 0 {
            let leading_zeros = limb.leading_zeros() as usize;
            let bit_index = (p.len() - 1 - i) * 64 + (64 - leading_zeros - 1);

            let is_exact_power_of_two = limb & (limb - 1) == 0;

            if is_exact_power_of_two {
                let all_lower_zeros = p[..i].iter().all(|&x| x == 0);
                return bit_index + (if all_lower_zeros { 0 } else { 1 });
            } else {
                return bit_index + 1;
            }
        }
    }

    panic!("log2(0) is undefined");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_to_field_different_messages_different_results() {
        let msg1 = b"test message 1";
        let msg2 = b"test message 2";
        let result1 = hash_to_field::<ark_secp256k1::Fq>(msg1);
        let result2 = hash_to_field::<ark_secp256k1::Fq>(msg2);
        assert_ne!(result1, result2);
    }
}
