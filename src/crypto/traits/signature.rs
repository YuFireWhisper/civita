use std::fmt::Debug;

use crate::{
    crypto::traits::{secret_key::SecretKey, PublicKey},
    traits::serializable::{ConstantSize, Serializable},
};

pub trait Signature:
    Clone + Debug + Eq + Serializable + ConstantSize + Sync + Send + 'static
{
}

pub trait Signer: SecretKey {
    type Signature: Signature;

    fn sign(&self, msg: &[u8]) -> Self::Signature;
}

pub trait VerifiySignature: PublicKey {
    type Signature: Signature;

    fn verify_signature(&self, msg: &[u8], sig: &Self::Signature) -> bool;
}
