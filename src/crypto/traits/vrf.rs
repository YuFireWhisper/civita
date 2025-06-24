use std::fmt::Debug;

use crate::{
    crypto::{
        error::*,
        traits::{hasher::HashArray, secret_key::SecretKey, Hasher, PublicKey},
    },
    traits::serializable::{ConstantSize, Serializable},
};

pub trait Proof: Clone + Debug + Eq + Serializable + ConstantSize + Sync + Send + 'static {
    type Hasher: Hasher;

    fn proof_to_hash(&self) -> HashArray<Self::Hasher>;
}

pub trait Prover: SecretKey + Eq {
    type Proof: Proof;

    fn prove(&self, alpha: &[u8]) -> Result<Self::Proof>;
}

pub trait VerifyProof: PublicKey {
    type Proof: Proof;

    fn verify_proof(&self, alpha: &[u8], proof: &Self::Proof) -> Result<()>;
}
