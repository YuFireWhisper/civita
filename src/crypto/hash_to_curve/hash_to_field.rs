use ark_ff::{Field, PrimeField};

use crate::crypto::hash_to_curve::expand_message_xmd::{self, expand_message_xmd};

type Result<T> = std::result::Result<T, Error>;

// IETF Step: Security parameter k = 128 bits
const K: usize = 128;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    ExpandMessage(#[from] expand_message_xmd::Error),
}

/// Implementation of hash_to_field as defined in IETF specification section 5.2
/// This function hashes a byte string into one or more elements of a field F
pub fn hash_to_field<F>(
    msg: impl AsRef<[u8]>,
    dst: impl AsRef<[u8]>,
    count: usize,
) -> Result<Vec<F>>
where
    F: Field,
{
    // IETF Step 0 (preparation): Calculate L = ceil((ceil(log2(p)) + k) / 8)
    let l = (ceil_log2(F::characteristic()) + K) / 8;

    // IETF Step 1: Calculate len_in_bytes = count * m * L
    // where m is the extension degree of F
    let len_in_bytes = count * F::extension_degree() as usize * l;

    // IETF Step 2: Generate uniform bytes using expand_message
    let uniform_bytes = expand_message_xmd(msg.as_ref(), dst.as_ref(), len_in_bytes)?;

    let mut u = Vec::with_capacity(count);
    // IETF Step 3: Loop through count elements to generate
    for i in 0..count {
        let mut e: Vec<F::BasePrimeField> = Vec::with_capacity(F::extension_degree() as usize);

        // IETF Step 4: For each component of the extension field
        for j in 0..F::extension_degree() {
            // IETF Step 5: Calculate element offset
            let elm_offset = l * (j as usize + i * F::extension_degree() as usize);

            // IETF Step 6: Extract substring of uniform bytes
            let tv = &uniform_bytes[elm_offset..elm_offset + l];

            // IETF Step 7: Convert to integer and reduce modulo p
            // (from_be_bytes_mod_order handles the OS2IP and modulo p operations)
            let e_j = F::BasePrimeField::from_be_bytes_mod_order(tv);
            e.push(e_j);
        }

        // IETF Step 8: Construct field element from components
        let u_i = F::from_base_prime_field_elems(e).expect("e.len != F::extension_degree()");
        u.push(u_i);
    }

    // IETF Step 9: Return the list of field elements
    Ok(u)
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
    use ark_ff::{Fp, MontBackend};

    #[derive(ark_ff::MontConfig)]
    #[modulus = "7"]
    #[generator = "3"]
    pub struct FqConfig;

    type TestField = Fp<MontBackend<FqConfig, 1>, 1>;

    const TEST_DST: &[u8] = b"CIVITA-TEST-DST";

    #[test]
    fn hash_to_field_normal_operation() {
        let msg = b"test message";
        let result = hash_to_field::<TestField>(msg, TEST_DST, 2);
        assert!(result.is_ok());
        let elements = result.unwrap();
        assert_eq!(elements.len(), 2);
    }

    #[test]
    fn hash_to_field_empty_message() {
        let msg = b"";
        let result = hash_to_field::<TestField>(msg, TEST_DST, 1);
        assert!(result.is_ok());
    }

    #[test]
    fn hash_to_field_count_zero_returns_empty() {
        let msg = b"test message";
        let result = hash_to_field::<TestField>(msg, TEST_DST, 0);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn hash_to_field_large_count_works() {
        let msg = b"test message";
        let result = hash_to_field::<TestField>(msg, TEST_DST, 100);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 100);
    }

    #[test]
    fn hash_to_field_different_messages_different_results() {
        let msg1 = b"test message 1";
        let msg2 = b"test message 2";
        let result1 = hash_to_field::<TestField>(msg1, TEST_DST, 1).unwrap();
        let result2 = hash_to_field::<TestField>(msg2, TEST_DST, 1).unwrap();
        assert_ne!(result1[0], result2[0]);
    }
}
