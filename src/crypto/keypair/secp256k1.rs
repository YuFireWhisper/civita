use bincode::{Decode, Encode};
use libsecp256k1::{self, PublicKey as LibPublicKey, PublicKeyFormat, SecretKey as LibSecretKey};
use serde::{Deserialize, Serialize};

const SECRET_KEY_LENGTH: usize = 32;
const PUBLIC_KEY_LENGTH: usize = 33;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Secp256k1(#[from] libsecp256k1::Error),

    #[error("Secret key not found")]
    SecretKeyNotFound,

    #[error("Invalid public key length")]
    InvalidPublicKeyLength,

    #[error("Invalid secret key length")]
    InvalidSecretKeyLength,

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Encode, Decode)]
#[derive(PartialEq, Eq)]
#[derive(Serialize, Deserialize)]
pub struct SecretKey([u8; SECRET_KEY_LENGTH]);

#[derive(Clone)]
#[derive(Debug)]
#[derive(Encode, Decode)]
#[derive(PartialEq, Eq)]
pub struct PublicKey([u8; PUBLIC_KEY_LENGTH]);

impl SecretKey {
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let _ = LibSecretKey::parse_slice(bytes)?;

        let mut key = [0u8; SECRET_KEY_LENGTH];
        key.copy_from_slice(bytes);

        Ok(Self(key))
    }

    pub fn from_secret_key(secret_key: &LibSecretKey) -> Self {
        Self(secret_key.serialize())
    }

    pub fn as_bytes(&self) -> &[u8; SECRET_KEY_LENGTH] {
        &self.0
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        ecies::decrypt(&self.0, ciphertext).map_err(Error::from)
    }
}

impl PublicKey {
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let _ = LibPublicKey::parse_slice(bytes, Some(PublicKeyFormat::Compressed))?;

        let mut key = [0u8; PUBLIC_KEY_LENGTH];
        key.copy_from_slice(bytes);

        Ok(Self(key))
    }

    pub fn from_public_key(public_key: &LibPublicKey) -> Self {
        Self(public_key.serialize_compressed())
    }

    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        &self.0
    }

    pub fn encrypt(&self, msg: &[u8]) -> Result<Vec<u8>> {
        ecies::encrypt(&self.0, msg).map_err(Error::from)
    }
}

pub fn generate_keypair() -> (SecretKey, PublicKey) {
    let (sk, pk) = ecies::utils::generate_keypair();
    (
        SecretKey::from_secret_key(&sk),
        PublicKey::from_public_key(&pk),
    )
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        let bytes = <Vec<u8>>::deserialize(deserializer)?;

        if bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(D::Error::custom(format!(
                "Invalid public key length: expected {}, got {}",
                PUBLIC_KEY_LENGTH,
                bytes.len()
            )));
        }

        let mut arr = [0u8; PUBLIC_KEY_LENGTH];
        arr.copy_from_slice(&bytes);

        PublicKey::from_slice(&arr)
            .map_err(|e| D::Error::custom(format!("Invalid public key: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::keypair::secp256k1::PublicKey;

    #[test]
    fn generate_keypair_is_valid() {
        let (sk, pk) = super::generate_keypair();

        assert_eq!(sk.as_bytes().len(), super::SECRET_KEY_LENGTH);
        assert_eq!(pk.as_bytes().len(), super::PUBLIC_KEY_LENGTH);
    }

    #[test]
    fn encrypt_decrypt() {
        const MESSAGE: &[u8] = b"Hello, world!";

        let (sk, pk) = super::generate_keypair();
        let ciphertext = pk.encrypt(MESSAGE).expect("Encryption failed");
        let decrypted = sk.decrypt(&ciphertext).expect("Decryption failed");

        assert_eq!(decrypted, MESSAGE);
    }

    #[test]
    fn fails_with_invalid_keys() {
        let invalid_public_key = vec![0u8; 0];
        assert!(PublicKey::from_slice(&invalid_public_key).is_err());
    }

    #[test]
    fn different_keys() {
        const MESSAGE: &[u8] = b"Hello, world!";

        let (sk1, pk1) = super::generate_keypair();
        let (sk2, pk2) = super::generate_keypair();

        assert_ne!(sk1.as_bytes(), sk2.as_bytes());
        assert_ne!(pk1.as_bytes(), pk2.as_bytes());

        let ciphertext = pk1.encrypt(MESSAGE).expect("Encryption failed");
        assert!(
            sk2.decrypt(&ciphertext).is_err(),
            "Decryption should fail with different keys"
        );
    }
}
