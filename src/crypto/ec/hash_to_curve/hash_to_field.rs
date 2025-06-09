use ark_ff::{
    fields::{Field, Zero},
    PrimeField,
};

use crate::crypto::ec::hash_to_curve::{config::Config, expand_message::ExpandMessage};

/// Implementation of hash_to_field as defined in IETF specification section 5.2
/// This function hashes a byte string into one element of a field F
pub fn hash_to_field<C: Config, const N: usize>(msg: impl AsRef<[u8]>) -> [C::BaseField; N] {
    let degree = C::BaseField::extension_degree() as usize;

    let len_in_bytes = N * degree * C::L;

    let uniform_bytes = C::ExpandMessage::expand_message(msg.as_ref(), C::DST, len_in_bytes);

    let mut u = [C::BaseField::zero(); N];

    (0..N).for_each(|i| {
        let mut e = Vec::with_capacity(degree);

        for j in 0..degree {
            let elm_offset = C::L * (j + i * degree);
            let tv = &uniform_bytes[elm_offset..elm_offset + C::L];
            let e_j = <C::BaseField as Field>::BasePrimeField::from_be_bytes_mod_order(tv);
            e.push(e_j);
        }

        let u_i =
            C::BaseField::from_base_prime_field_elems(e).expect("e.len != F::extension_degree()");
        u[i] = u_i;
    });

    u
}
