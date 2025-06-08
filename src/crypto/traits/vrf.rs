use crate::crypto::{
    self,
    traits::{public_key::PublicKey, secret_key::SecretKey},
};

pub trait Prover: SecretKey {
    type Proof;

    fn prove(&self, alpha: &[u8]) -> Result<Self::Proof, crypto::Error>;
}

pub trait Verifier: PublicKey {
    type Proof;

    fn verify(&self, alpha: &[u8], pi: Self::Proof) -> Result<Vec<u8>, crypto::Error>;
}
