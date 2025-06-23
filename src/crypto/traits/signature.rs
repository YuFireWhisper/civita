use std::fmt::Debug;

use crate::{
    crypto::{
        error::*,
        traits::{secret_key::SecretKey, PublicKey},
    },
    traits::serializable::Serializable,
};

pub trait Signature: Clone + Debug + Eq + Serializable + Sync + Send + 'static {}

pub trait Signer: SecretKey {
    type Signature: Signature;

    fn sign(&self, msg: &[u8]) -> Result<Self::Signature>;
}

pub trait VerifiySignature: PublicKey {
    type Signature: Signature;

    fn verify_signature(&self, msg: &[u8], sig: &Self::Signature) -> Result<()>;
}
