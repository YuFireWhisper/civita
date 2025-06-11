use crate::crypto::{
    self,
    traits::{hasher::Output, secret_key::SecretKey, Hasher, PublicKey},
};

pub trait Proof<H: Hasher>: Sized {
    fn proof_to_hash(&self) -> Output<H>;
    fn from_bytes(bytes: &[u8]) -> Result<Self, crypto::Error>;
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait Prover<P: Proof<H>, H: Hasher>: SecretKey {
    fn prove(&self, alpha: &[u8]) -> P;
}

pub trait VerifyProof<P: Proof<H>, H: Hasher>: PublicKey {
    fn verify_proof(&self, alpha: &[u8], proof: &P) -> bool;
}
