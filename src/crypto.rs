use serde::{Deserialize, Serialize};

pub mod algebra;
pub mod dkg;
pub mod ec;
pub mod error;
pub mod keypair;
pub mod threshold;
pub mod traits;
pub mod tss;
pub mod types;
pub mod vss;

pub use error::Error;
pub use traits::hasher::Output as HashOutput;
pub use traits::Hasher;

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

impl<S: traits::Suite> traits::vrf::Prover<S::Proof, S::Hasher> for SecretKey<S> {
    fn prove(&self, msg: &[u8]) -> S::Proof {
        self.0.prove(msg)
    }
}

impl<S: traits::Suite> traits::Signer<S::Signature> for SecretKey<S> {
    fn sign(&self, msg: &[u8]) -> S::Signature {
        self.0.sign(msg)
    }
}

impl<SU: traits::Suite> Serialize for SecretKey<SU> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use traits::SecretKey;
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de, S: traits::Suite> Deserialize<'de> for SecretKey<S> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use traits::SecretKey;
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        SecretKey::from_slice(&bytes).map_err(|e| serde::de::Error::custom(e.to_string()))
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

impl<S: traits::Suite> traits::vrf::VerifyProof<S::Proof, S::Hasher> for PublicKey<S> {
    fn verify_proof(&self, msg: &[u8], proof: &S::Proof) -> bool {
        self.0.verify_proof(msg, proof)
    }
}

impl<S: traits::Suite> traits::VerifiySignature<S::Signature> for PublicKey<S> {
    fn verify_signature(&self, msg: &[u8], sig: &S::Signature) -> bool {
        self.0.verify_signature(msg, sig)
    }
}

impl<SU: traits::Suite> Serialize for PublicKey<SU> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use traits::PublicKey;
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de, S: traits::Suite> Deserialize<'de> for PublicKey<S> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use traits::PublicKey;
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        PublicKey::from_slice(&bytes).map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

impl<S: traits::Suite> traits::vrf::Proof<S::Hasher> for Proof<S> {
    fn proof_to_hash(&self) -> traits::hasher::Output<S::Hasher> {
        self.0.proof_to_hash()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, self::Error> {
        S::Proof::from_bytes(bytes).map(Proof)
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}

impl<SU: traits::Suite> Serialize for Proof<SU> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use traits::vrf::Proof;
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de, S: traits::Suite> Deserialize<'de> for Proof<S> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use traits::vrf::Proof;
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Proof::from_bytes(&bytes).map_err(|e| serde::de::Error::custom(e.to_string()))
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

impl<SU: traits::Suite> Serialize for Signature<SU> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use traits::Signature;
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de, S: traits::Suite> Deserialize<'de> for Signature<S> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use traits::Signature;
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Signature::from_slice(&bytes).map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}
