use crate::traits::serializable;

pub mod public_key;
pub mod secret_key;

mod hash_to_curve;
mod signature;
mod suite_implements;
mod vrf;

impl From<ark_serialize::SerializationError> for serializable::Error {
    fn from(e: ark_serialize::SerializationError) -> Self {
        serializable::Error(e.to_string())
    }
}
