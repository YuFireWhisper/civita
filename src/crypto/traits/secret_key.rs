use std::fmt::Debug;

use crate::crypto;

pub trait SecretKey: Clone + Debug + Eq + Sized + Sync + Send + 'static {
    type PublicKey;

    fn random() -> Self;
    fn from_slice(slice: &[u8]) -> Result<Self, crypto::Error>;
    fn to_bytes(&self) -> Vec<u8>;
    fn public_key(&self) -> Self::PublicKey;
}
