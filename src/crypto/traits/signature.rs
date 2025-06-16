use std::fmt::Debug;

use crate::crypto::{
    self,
    traits::{secret_key::SecretKey, PublicKey},
};

pub trait Signature: Clone + Debug + Eq + Sized + Sync + Send + 'static {
    fn from_slice(bytes: &[u8]) -> Result<Self, crypto::Error>;
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait Signer: SecretKey {
    type Signature: Signature;

    fn sign(&self, msg: &[u8]) -> Self::Signature;
}

pub trait VerifiySignature: PublicKey {
    type Signature: Signature;

    fn verify_signature(&self, msg: &[u8], sig: &Self::Signature) -> bool;
}
