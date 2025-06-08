use crate::crypto::{
    self,
    traits::{public_key::PublicKey, secret_key::SecretKey},
};

pub trait Signer: SecretKey {
    type Signature;

    fn sign(&self, msg: &[u8]) -> Result<Self::Signature, crypto::Error>;
}

pub trait Verifier: PublicKey {
    type Signature;

    fn verify(&self, msg: &[u8], sig: &Self::Signature) -> Result<bool, crypto::Error>;
}
