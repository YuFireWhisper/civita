use crate::{crypto::Hasher, traits::serializable};

pub mod public_key;
pub mod secret_key;
pub mod signature;
pub mod vrf;

mod hash_to_curve;
mod suite_implements;

pub use secret_key::SecretKey;
pub use signature::Signature;

pub trait HasherConfig {
    type Hasher: Hasher;
}

impl From<ark_serialize::SerializationError> for serializable::Error {
    fn from(e: ark_serialize::SerializationError) -> Self {
        serializable::Error(e.to_string())
    }
}
