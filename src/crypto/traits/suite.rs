use crate::crypto::traits::{
    public_key::PublicKey,
    secret_key::SecretKey,
    vrf::{self},
    Hasher, Signature, Signer, VerifiySignature,
};

pub trait Suite: 'static {
    type SecretKey: SecretKey<PublicKey = Self::PublicKey>
        + vrf::Prover<Proof = Self::Proof>
        + Signer<Signature = Self::Signature>;
    type PublicKey: PublicKey
        + vrf::VerifyProof<Proof = Self::Proof>
        + VerifiySignature<Signature = Self::Signature>;
    type Proof: vrf::Proof<Hasher = Self::Hasher>;
    type Signature: Signature;
    type Hasher: Hasher;
}
