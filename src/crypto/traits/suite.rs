use crate::crypto::traits::{
    public_key::PublicKey,
    secret_key::SecretKey,
    vrf::{self, Proof},
    Hasher, Signature, Signer, VerifiySignature,
};

pub trait Suite {
    type SecretKey: SecretKey<PublicKey = Self::PublicKey>
        + vrf::Prover<Self::Proof, Self::Hasher>
        + Signer<Self::Signature>;
    type PublicKey: PublicKey
        + vrf::VerifyProof<Self::Proof, Self::Hasher>
        + VerifiySignature<Self::Signature>;
    type Proof: Proof<Self::Hasher>;
    type Signature: Signature;
    type Hasher: Hasher;
}
