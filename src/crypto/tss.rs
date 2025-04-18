pub mod schnorr;

pub trait Tss {
    type Error;
    type Signature;

    fn sign(&self, seed: Option<&[u8]>, msg: &[u8]) -> Result<Self::Signature, Self::Error>;
    fn verify(&self, msg: &[u8], sig: &Self::Signature) -> bool;
}
