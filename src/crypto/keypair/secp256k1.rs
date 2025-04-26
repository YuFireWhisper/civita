use bincode::{Decode, Encode};
use k256::{
    elliptic_curve::{rand_core::OsRng, sec1::ToEncodedPoint},
    PublicKey as K256PublicKey, SecretKey as K256SecretKey,
};
use serde::{Deserialize, Serialize};

const SECRET_KEY_LENGTH: usize = 32;
const PUBLIC_KEY_LENGTH: usize = 33;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    EllipticCurve(#[from] k256::elliptic_curve::Error),

    #[error("{0}")]
    Ecies(String),

    #[error("{0}")]
    Ecvrf(String),
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
    pub fn random() -> Self {
        let secret_key: K256SecretKey = K256SecretKey::random(&mut OsRng);
        Self::from(&secret_key)
    }

    pub fn to_public_key(&self) -> PublicKey {
        self.into()
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        Self::try_from(bytes)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        ecies::decrypt(&self.0, ciphertext).map_err(|e| Error::Ecies(e.to_string()))
    }

    pub fn prove(&self, input: impl AsRef<[u8]>) -> Result<libecvrf_k256::ECVRFProof> {
        let ecvrf = libecvrf_k256::ECVRF::new_from_bytes(&self.0)
            .map_err(|e| Error::Ecvrf(e.to_string()))?;

        ecvrf
            .prove(input.as_ref())
            .map_err(|e| Error::Ecvrf(e.to_string()))
    }
}

impl PublicKey {
    pub fn random() -> Self {
        let secret_key = SecretKey::random();
        Self::from_secret_key(&secret_key)
    }

    pub fn from_secret_key(secret_key: &SecretKey) -> Self {
        Self::from(secret_key)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        Self::try_from(bytes)
    }

    pub fn encrypt(&self, msg: &[u8]) -> Result<Vec<u8>> {
        ecies::encrypt(&self.0, msg).map_err(|e| Error::Ecies(e.to_string()))
    }

    pub fn verify_proof(&self, input: impl AsRef<[u8]>, proof: &libecvrf_k256::ECVRFProof) -> bool {
        libecvrf_k256::ECVRF::verify(input.as_ref(), proof, &self.0)
    }
}

pub fn generate_keypair() -> (SecretKey, PublicKey) {
    let secret_key = SecretKey::random();
    let public_key = PublicKey::from_secret_key(&secret_key);
    (secret_key, public_key)
}

impl From<&k256::SecretKey> for SecretKey {
    fn from(secret_key: &k256::SecretKey) -> Self {
        Self(secret_key.to_bytes().into())
    }
}

impl From<&SecretKey> for k256::SecretKey {
    fn from(secret_key: &SecretKey) -> Self {
        k256::SecretKey::from_slice(secret_key.as_ref()).expect("Invalid secret key")
    }
}

impl TryFrom<&[u8]> for SecretKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        let key = K256SecretKey::from_slice(bytes)?;
        Ok(Self::from(&key))
    }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<&k256::PublicKey> for PublicKey {
    fn from(public_key: &k256::PublicKey) -> Self {
        let mut arr = [0u8; PUBLIC_KEY_LENGTH];
        arr.copy_from_slice(&public_key.to_encoded_point(true).to_bytes());
        Self(arr)
    }
}

impl From<&SecretKey> for PublicKey {
    fn from(secret_key: &SecretKey) -> Self {
        let secret_key =
            K256SecretKey::from_slice(secret_key.as_ref()).expect("Invalid secret key");
        let public_key = secret_key.public_key();
        Self::from(&public_key)
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        let key = K256PublicKey::from_sec1_bytes(bytes)?;

        let mut arr = [0u8; PUBLIC_KEY_LENGTH];
        arr.copy_from_slice(&key.to_encoded_point(true).to_bytes());

        Ok(Self(arr))
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
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

        PublicKey::from_slice(&bytes)
            .map_err(|e| D::Error::custom(format!("Invalid public key: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::keypair::secp256k1::{PublicKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};

    #[test]
    fn generate_keypair_is_valid() {
        let (sk, pk) = super::generate_keypair();

        assert_eq!(sk.as_ref().len(), SECRET_KEY_LENGTH);
        assert_eq!(pk.as_ref().len(), PUBLIC_KEY_LENGTH);
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

        assert_ne!(sk1, sk2);
        assert_ne!(pk1, pk2);

        let ciphertext = pk1.encrypt(MESSAGE).expect("Encryption failed");
        assert!(
            sk2.decrypt(&ciphertext).is_err(),
            "Decryption should fail with different keys"
        );
    }

    #[test]
    fn vrf_success() {
        const MESSAGE: &[u8] = b"Hello, world!";

        let (sk, pk) = super::generate_keypair();
        let proof = sk.prove(MESSAGE);
        assert!(proof.is_ok(), "VRF proof generation failed");
        assert!(
            pk.verify_proof(MESSAGE, &proof.unwrap()),
            "VRF proof verification failed"
        );
    }
}
