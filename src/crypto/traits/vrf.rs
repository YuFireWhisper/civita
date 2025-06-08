use crate::crypto::{self, traits::secret_key::SecretKey};

pub trait Vrf<S: SecretKey> {
    fn prove(sk: &S, alpha: &[u8]) -> Result<Vec<u8>, crypto::Error>;
    fn verify(pk: &S::PublicKey, alpha: &[u8], pi: &[u8]) -> Result<Vec<u8>, crypto::Error>;
}
