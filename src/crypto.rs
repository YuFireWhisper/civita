use std::fmt::Debug;

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
pub use traits::Hasher;

pub struct SecretKey<S: traits::Suite>(pub(crate) S::SecretKey);
pub struct PublicKey<S: traits::Suite>(pub(crate) S::PublicKey);
pub struct Proof<S: traits::Suite>(pub(crate) S::Proof);
pub struct Signature<S: traits::Suite>(pub(crate) S::Signature);

impl<S: traits::Suite> traits::vrf::Prover for SecretKey<S> {
    type Proof = S::Proof;

    fn prove(&self, msg: &[u8]) -> S::Proof {
        self.0.prove(msg)
    }
}

impl<S: traits::Suite> traits::Signer for SecretKey<S> {
    type Signature = S::Signature;

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

impl<S: traits::Suite> Clone for SecretKey<S> {
    fn clone(&self) -> Self {
        SecretKey(self.0.clone())
    }
}

impl<S: traits::Suite> Debug for SecretKey<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use traits::SecretKey;

        let bytes = self.to_bytes();

        write!(
            f,
            "SecretKey {{ len: {}, first_4_bytes: {:02x?} }}",
            bytes.len(),
            &bytes[..4.min(bytes.len())]
        )
    }
}

impl<S: traits::Suite> PartialEq for SecretKey<S> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<S: traits::Suite> Eq for SecretKey<S> {}

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

impl<S: traits::Suite> traits::PublicKey for PublicKey<S> {
    fn from_slice(slice: &[u8]) -> Result<Self, self::Error> {
        S::PublicKey::from_slice(slice).map(PublicKey)
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}

impl<S: traits::Suite> traits::vrf::VerifyProof for PublicKey<S> {
    type Proof = S::Proof;

    fn verify_proof(&self, msg: &[u8], proof: &S::Proof) -> bool {
        self.0.verify_proof(msg, proof)
    }
}

impl<S: traits::Suite> traits::VerifiySignature for PublicKey<S> {
    type Signature = S::Signature;

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

impl<S: traits::Suite> Clone for PublicKey<S> {
    fn clone(&self) -> Self {
        PublicKey(self.0.clone())
    }
}

impl<S: traits::Suite> Debug for PublicKey<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use traits::PublicKey;

        let bytes = self.to_bytes();

        write!(
            f,
            "PublicKey {{ len: {}, first_4_bytes: {:02x?} }}",
            bytes.len(),
            &bytes[..4.min(bytes.len())]
        )
    }
}

impl<S: traits::Suite> PartialEq for PublicKey<S> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<S: traits::Suite> Eq for PublicKey<S> {}

impl<S: traits::Suite> traits::vrf::Proof for Proof<S> {
    type Hasher = S::Hasher;

    fn proof_to_hash(&self) -> traits::hasher::HashArray<S::Hasher> {
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

impl<S: traits::Suite> Clone for Proof<S> {
    fn clone(&self) -> Self {
        Proof(self.0.clone())
    }
}

impl<S: traits::Suite> Debug for Proof<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<S: traits::Suite> PartialEq for Proof<S> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<S: traits::Suite> Eq for Proof<S> {}

impl<S: traits::Suite> traits::Signature for Signature<S> {
    fn from_slice(bytes: &[u8]) -> Result<Self, self::Error> {
        Ok(Self(<S::Signature as traits::Signature>::from_slice(
            bytes,
        )?))
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

impl<S: traits::Suite> Clone for Signature<S> {
    fn clone(&self) -> Self {
        Signature(self.0.clone())
    }
}

impl<S: traits::Suite> Debug for Signature<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<S: traits::Suite> PartialEq for Signature<S> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<S: traits::Suite> Eq for Signature<S> {}
