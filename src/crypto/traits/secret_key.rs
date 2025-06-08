use crate::crypto;

pub trait SecretKey: Sized {
    type PublicKey;

    fn random() -> Self;
    fn from_slice(slice: &[u8]) -> Result<Self, crypto::Error>;
    fn to_bytes(&self) -> Vec<u8>;
    fn to_public_key(&self) -> Self::PublicKey;
}
