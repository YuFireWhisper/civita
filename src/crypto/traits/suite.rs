use crate::crypto::traits::{
    self,
    secret_key::SecretKey,
    vrf::{self},
    Signer, VerifiySignature,
};

pub trait HasherConfig {
    type Hasher: traits::Hasher;
}

pub trait Suite: HasherConfig + 'static {
    type SecretKey: SecretKey<PublicKey = Self::PublicKey>
        + vrf::Prover<Proof = Self::Proof>
        + Signer<Signature = Self::Signature>;
    type PublicKey: traits::PublicKey
        + vrf::VerifyProof<Proof = Self::Proof>
        + VerifiySignature<Signature = Self::Signature>;
    type Proof: vrf::Proof<Hasher = Self::Hasher>;
    type Signature: traits::Signature;
}
