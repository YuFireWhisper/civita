use crate::crypto::{self, traits::suite::Suite};

pub trait Proof {
    fn to_output(&self) -> Vec<u8>;
}

pub trait Vrf: Suite {
    type Proof: Proof;

    fn prove(secret_key: &Self::SecretKey, input: &[u8]) -> Self::Proof;
    fn verify(
        public_key: &Self::PublicKey,
        input: &[u8],
        proof: &Self::Proof,
    ) -> Result<Vec<u8>, crypto::Error>;
}
