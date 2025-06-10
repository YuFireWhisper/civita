use crate::crypto::traits::{
    public_key::PublicKey,
    secret_key::SecretKey,
    vrf::{self, Proof},
    Signature, Signer, VerifiySignature,
};

pub trait Suite {
    type SecretKey: SecretKey<PublicKey = Self::PublicKey>
        + vrf::Prover<Self::Proof>
        + Signer<Self::Signature>;
    type PublicKey: PublicKey + vrf::VerifyProof<Self::Proof> + VerifiySignature<Self::Signature>;
    type Proof: Proof;
    type Signature: Signature;
}
