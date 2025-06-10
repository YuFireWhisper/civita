use crate::crypto::traits::secret_key::SecretKey;

pub trait Vrf: SecretKey {
    type Proof;

    fn prove(&self, alpha: &[u8]) -> Self::Proof;
    fn verify(pk: Self::PublicKey, alpha: &[u8], proof: &Self::Proof) -> bool;
    fn proof_to_hash(proof: &Self::Proof) -> Vec<u8>;
}
