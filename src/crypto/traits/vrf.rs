use std::fmt::Debug;

use crate::crypto::{
    self,
    traits::{hasher::HashArray, secret_key::SecretKey, Hasher, PublicKey},
};

pub trait Proof: Clone + Debug + Eq + Sized + Sync + Send + 'static {
    type Hasher: Hasher;

    fn proof_to_hash(&self) -> HashArray<Self::Hasher>;
    fn from_bytes(bytes: &[u8]) -> Result<Self, crypto::Error>;
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait Prover: SecretKey + Eq {
    type Proof: Proof;

    fn prove(&self, alpha: &[u8]) -> Self::Proof;
}

pub trait VerifyProof: PublicKey {
    type Proof: Proof;

    fn verify_proof(&self, alpha: &[u8], proof: &Self::Proof) -> bool;
}
