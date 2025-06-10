use crate::crypto::traits::secret_key::SecretKey;

pub trait Signature: SecretKey {
    type Signature;

    fn sign(&self, msg: &[u8]) -> Self::Signature;
    fn verify(pk: Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> bool;
}
