use crate::crypto::{
    self,
    traits::{secret_key::SecretKey, PublicKey},
};

pub trait Proof: Sized {
    fn proof_to_hash(&self) -> Vec<u8>;
    fn from_bytes(bytes: &[u8]) -> Result<Self, crypto::Error>;
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait Prover<P: Proof>: SecretKey {
    fn prove(&self, alpha: &[u8]) -> P;
}

pub trait VerifyProof<P: Proof>: PublicKey {
    fn verify_proof(&self, alpha: &[u8], proof: &P) -> bool;
}
