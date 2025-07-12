use crate::crypto::traits::{secret_key::SecretKey, PublicKey};

pub trait Signer: SecretKey {
    type Signature;

    fn sign(&self, msg: &[u8]) -> Self::Signature;
}

pub trait VerifiySignature: PublicKey {
    type Signature;

    fn verify_signature(&self, msg: &[u8], sig: &Self::Signature) -> bool;
}
