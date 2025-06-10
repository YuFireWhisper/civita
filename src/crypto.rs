pub mod algebra;
pub mod dkg;
pub mod ec;
pub mod error;
pub mod keypair;
pub mod threshold;
pub mod traits;
pub mod tss;
pub mod types;
pub mod vss;

pub use error::Error;

pub struct SecretKey<S>(pub(crate) S::SecretKey)
where
    S: traits::Suite,
    S::SecretKey: traits::Vrf + traits::Signature;

pub struct PublicKey<S: traits::Suite>(pub(crate) S::PublicKey);
