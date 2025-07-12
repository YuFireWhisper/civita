use std::fmt::Debug;

use crate::{
    crypto::traits::{hasher::Multihash, secret_key::SecretKey, PublicKey},
    traits::serializable::Serializable,
};

pub trait Proof: Clone + Debug + Eq + Serializable + Sync + Send + 'static {
    fn proof_to_hash(&self) -> Multihash;
}

pub trait Prover: SecretKey + Eq {
    type Proof: Proof;

    fn prove(&self, alpha: &[u8]) -> Self::Proof;
}

pub trait VerifyProof: PublicKey {
    type Proof: Proof;

    fn verify_proof(&self, alpha: &[u8], proof: &Self::Proof) -> bool;
}
