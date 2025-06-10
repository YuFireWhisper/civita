use crate::crypto::{
    self,
    traits::{secret_key::SecretKey, PublicKey},
};

pub trait Signature: Sized {
    fn from_slice(bytes: &[u8]) -> Result<Self, crypto::Error>;
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait Signer<S: Signature>: SecretKey {
    fn sign(&self, msg: &[u8]) -> S;
}

pub trait VerifiySignature<S: Signature>: PublicKey {
    fn verify_signature(&self, msg: &[u8], sig: &S) -> bool;
}
