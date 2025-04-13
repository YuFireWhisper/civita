use bincode::{Decode, Encode};
use ecies::{PublicKey, SecretKey};
use libsecp256k1::PublicKeyFormat;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Ecies(#[from] libsecp256k1::Error),

    #[error("Secret key not found")]
    SecretKeyNotFound,
}

#[derive(Debug)]
#[derive(Encode, Decode)]
pub struct Ecies {
    secret_key: Option<Vec<u8>>,
    public_key: Vec<u8>,
}

impl Ecies {
    pub fn generate() -> Self {
        let (sk, pk) = ecies::utils::generate_keypair();
        Self::from_keypair(sk, pk)
    }

    pub fn from_keypair(secret_key: SecretKey, public_key: PublicKey) -> Self {
        Self {
            secret_key: Some(secret_key.serialize().to_vec()),
            public_key: public_key.serialize_compressed().to_vec(),
        }
    }

    pub fn from_secret_key_slice(secret_key: &[u8]) -> Result<Self> {
        let secret_key = SecretKey::parse_slice(secret_key)?;
        let public_key = PublicKey::from_secret_key(&secret_key);
        Ok(Self::from_keypair(secret_key, public_key))
    }

    pub fn from_public_key_slice(public_key: &[u8]) -> Result<Self> {
        Self::verify_public_key_bytes(public_key)?;

        Ok(Self {
            secret_key: None,
            public_key: public_key.to_vec(),
        })
    }

    fn verify_public_key_bytes(public_key: &[u8]) -> Result<()> {
        let _ = PublicKey::parse_slice(public_key, Some(PublicKeyFormat::Compressed))?;
        Ok(())
    }

    pub fn encrypt(&self, msg: &[u8]) -> Result<Vec<u8>> {
        ecies::encrypt(self.public_key(), msg).map_err(Error::from)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if let Some(secret_key) = &self.secret_key {
            ecies::decrypt(secret_key, ciphertext).map_err(Error::from)
        } else {
            Err(Error::SecretKeyNotFound)
        }
    }

    pub fn secret_key(&self) -> Option<&Vec<u8>> {
        self.secret_key.as_ref()
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::keypair::ecies::Ecies;

    #[test]
    fn generate_keypair_is_not_none() {
        let ecies = Ecies::generate();
        assert!(ecies.secret_key().is_some());
        assert!(!ecies.public_key().is_empty());
    }

    #[test]
    fn some_message_after_encryption_and_decryption() {
        const MESSAGE: &[u8] = b"Hello, world!";

        let ecies = Ecies::generate();
        let ciphertext = ecies.encrypt(MESSAGE).expect("Encryption failed");
        let decrypted_message = ecies.decrypt(&ciphertext).expect("Decryption failed");

        assert_eq!(MESSAGE, decrypted_message.as_slice());
    }

    #[test]
    fn failed_decryption_without_secret_key() {
        const MESSAGE: &[u8] = b"Hello, world!";

        let ecies = Ecies::generate();
        let ciphertext = ecies.encrypt(MESSAGE).expect("Encryption failed");

        let ecies_without_secret_key = Ecies::from_public_key_slice(ecies.public_key()).unwrap();
        let result = ecies_without_secret_key.decrypt(&ciphertext);

        assert!(result.is_err());
    }
}
