use crate::crypto::traits::{
    self,
    secret_key::SecretKey,
    vrf::{self},
    Signer, VerifiySignature,
};

pub type Hasher<S> = <S as HasherConfig>::Hasher;
pub type PublicKey<S> = <S as Suite>::PublicKey;
pub type Proof<S> = <S as Suite>::Proof;
pub type Signature<S> = <S as Suite>::Signature;

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
