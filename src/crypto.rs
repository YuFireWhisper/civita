pub mod algebra;
pub mod dkg;
pub mod error;
pub mod keypair;
pub mod threshold;
pub mod tss;
pub mod types;
pub mod vss;

mod ec;
mod traits;

pub use error::Error;

pub struct SecretKey<S: traits::Suite>(pub(crate) S::SecretKey);
pub struct PublicKey<S: traits::Suite>(pub(crate) S::PublicKey);
pub struct Proof<S: traits::Suite>(pub(crate) S::Proof);
pub struct Signature<S: traits::Suite>(pub(crate) S::Signature);

impl<S: traits::Suite> traits::SecretKey for SecretKey<S> {
    type PublicKey = PublicKey<S>;

    fn random() -> Self {
        SecretKey(S::SecretKey::random())
    }

    fn from_slice(slice: &[u8]) -> Result<Self, self::Error> {
        S::SecretKey::from_slice(slice).map(SecretKey)
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    fn to_public_key(&self) -> Self::PublicKey {
        PublicKey(self.0.to_public_key())
    }
}

impl<S: traits::Suite> traits::vrf::Prover<S::Proof> for SecretKey<S> {
    fn prove(&self, msg: &[u8]) -> S::Proof {
        self.0.prove(msg)
    }
}

impl<S: traits::Suite> traits::Signer<S::Signature> for SecretKey<S> {
    fn sign(&self, msg: &[u8]) -> S::Signature {
        self.0.sign(msg)
    }
}

impl<S: traits::Suite> traits::PublicKey for PublicKey<S> {
    fn from_slice(slice: &[u8]) -> Result<Self, self::Error> {
        S::PublicKey::from_slice(slice).map(PublicKey)
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}

impl<S: traits::Suite> traits::vrf::VerifyProof<S::Proof> for PublicKey<S> {
    fn verify_proof(&self, msg: &[u8], proof: &S::Proof) -> bool {
        self.0.verify_proof(msg, proof)
    }
}

impl<S: traits::Suite> traits::VerifiySignature<S::Signature> for PublicKey<S> {
    fn verify_signature(&self, msg: &[u8], sig: &S::Signature) -> bool {
        self.0.verify_signature(msg, sig)
    }
}

impl<S: traits::Suite> traits::vrf::Proof for Proof<S> {
    fn proof_to_hash(&self) -> Vec<u8> {
        self.0.proof_to_hash()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, self::Error> {
        S::Proof::from_bytes(bytes).map(Proof)
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}

impl<S: traits::Suite> traits::Signature for Signature<S> {
    fn from_slice(bytes: &[u8]) -> Result<Self, self::Error> {
        S::Signature::from_slice(bytes).map(Signature)
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}
