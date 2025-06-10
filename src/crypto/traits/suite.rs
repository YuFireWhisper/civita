use crate::crypto::traits::{
    public_key::PublicKey,
    secret_key::SecretKey,
    vrf::{self, Proof},
};

pub trait Suite {
    type SecretKey: SecretKey<PublicKey = Self::PublicKey> + vrf::Prove<Self::Proof>;
    type PublicKey: PublicKey + vrf::VerifyProof<Self::Proof>;
    type Proof: Proof;
}
