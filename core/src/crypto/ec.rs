use crate::crypto::Hasher;

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
