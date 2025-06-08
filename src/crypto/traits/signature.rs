use crate::crypto::{self, traits::secret_key::SecretKey};

pub trait Signature<S: SecretKey> {
    fn sign(sk: &S, msg: &[u8]) -> Result<Vec<u8>, crypto::Error>;
    fn verify(pk: &S::PublicKey, msg: &[u8], sig: &[u8]) -> Result<bool, crypto::Error>;
}
