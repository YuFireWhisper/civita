use crate::crypto::primitives::algebra::element::{Public, Secret};

pub trait Tss<SK, PK>
where
    SK: Secret,
    PK: Public,
{
    type Error;
    type Signature;

    fn sign(&self, seed: Option<&[u8]>, msg: &[u8]) -> Result<Self::Signature, Self::Error>;
    fn verify(&self, msg: &[u8], sig: &Self::Signature) -> bool;
}
