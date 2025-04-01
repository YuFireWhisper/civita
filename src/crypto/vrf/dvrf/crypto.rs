use mockall::automock;
use p256::ecdsa::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use std::sync::{Mutex, MutexGuard, PoisonError};
use thiserror::Error;
use vrf::{
    openssl::{CipherSuite, ECVRF},
    VRF,
};

use super::proof::Proof;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to create ECVRF instance: {0}")]
    EcvrfCreation(String),
    #[error("Failed to lock VRF: {0}")]
    Lock(String),
}

type Result<T> = std::result::Result<T, Error>;

#[automock]
pub trait Crypto: Send + Sync {
    fn generate_proof(&self, seed: &[u8]) -> Result<Proof>;
    fn verify_proof(&self, public_key: &[u8], proof: &[u8], seed: &[u8]) -> Result<Vec<u8>>;
    fn public_key(&self) -> &[u8];
}

pub struct EcvrfCrypto {
    vrf: Mutex<ECVRF>,
    private_key: Vec<u8>,
    public_key: Vec<u8>,
}

impl EcvrfCrypto {
    pub fn new() -> Result<Self> {
        let vrf_instance = ECVRF::from_suite(CipherSuite::P256_SHA256_TAI)?;
        let (private_key, public_key) = Self::generate_keypair();

        Ok(Self {
            vrf: Mutex::new(vrf_instance),
            private_key,
            public_key,
        })
    }

    fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
        let mut rng = OsRng;
        let signing_key = SigningKey::random(&mut rng);
        let verifying_key = VerifyingKey::from(&signing_key);
        let private_key = signing_key.to_bytes().to_vec();
        let public_key = verifying_key.to_encoded_point(false).as_bytes().to_vec();
        (private_key, public_key)
    }

    fn get_vrf(&self) -> Result<MutexGuard<'_, ECVRF>> {
        self.vrf.lock().map_err(Error::from)
    }

    #[cfg(test)]
    pub fn with_keypair(private_key: Vec<u8>, public_key: Vec<u8>) -> Result<Self> {
        let vrf_instance = ECVRF::from_suite(CipherSuite::P256_SHA256_TAI)?;

        Ok(Self {
            vrf: Mutex::new(vrf_instance),
            private_key,
            public_key,
        })
    }
}

impl Crypto for EcvrfCrypto {
    fn generate_proof(&self, seed: &[u8]) -> Result<Proof> {
        let mut vrf = self.get_vrf()?;
        let proof = vrf.prove(self.private_key.as_slice(), seed)?;
        let output = vrf.proof_to_hash(&proof)?;
        Ok(Proof::new(output, proof))
    }

    fn verify_proof(&self, public_key: &[u8], proof: &[u8], seed: &[u8]) -> Result<Vec<u8>> {
        let mut vrf = self.get_vrf()?;
        vrf.verify(public_key, proof, seed).map_err(Error::from)
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

impl From<vrf::openssl::Error> for Error {
    fn from(err: vrf::openssl::Error) -> Self {
        Error::EcvrfCreation(format!("{:?}", err))
    }
}

impl From<PoisonError<MutexGuard<'_, ECVRF>>> for Error {
    fn from(err: PoisonError<MutexGuard<'_, ECVRF>>) -> Self {
        Error::Lock(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED: &[u8] = b"test_seed";

    #[test]
    fn test_new_success() {
        let crypto = EcvrfCrypto::new();
        assert!(crypto.is_ok());
    }

    #[test]
    fn test_new_items() {
        let crypto = EcvrfCrypto::new().unwrap();
        assert_eq!(
            crypto.private_key.len(),
            32,
            "Private key should be 32 bytes"
        );
        assert_eq!(crypto.public_key.len(), 65, "Public key should be 65 bytes");
    }

    #[test]
    fn test_generate_proof_success() {
        let crypto = EcvrfCrypto::new().unwrap();
        let proof = crypto.generate_proof(TEST_SEED);
        assert!(proof.is_ok(), "Proof generation should succeed");
    }

    #[test]
    fn test_generate_proof_items() {
        let crypto = EcvrfCrypto::new().unwrap();
        let proof = crypto.generate_proof(TEST_SEED).unwrap();
        assert_eq!(proof.output().len(), 32, "Proof output should be 32 bytes");
        assert_eq!(proof.proof().len(), 81, "Proof should be 81 bytes");
    }

    #[test]
    fn test_verify_proof_success() {
        let crypto = EcvrfCrypto::new().unwrap();
        let proof = crypto.generate_proof(TEST_SEED).unwrap();
        let public_key = crypto.public_key().to_vec();
        let result = crypto.verify_proof(&public_key, proof.proof(), TEST_SEED);
        assert!(result.is_ok(), "Proof verification should succeed");
    }

    #[test]
    fn test_verify_proof_invalid_public_key() {
        let crypto = EcvrfCrypto::new().unwrap();
        let proof = crypto.generate_proof(TEST_SEED).unwrap();
        let public_key = vec![0; 65];
        let result = crypto.verify_proof(&public_key, proof.proof(), TEST_SEED);
        assert!(result.is_err(), "Proof verification should fail");
    }

    #[test]
    fn test_verify_proof_invalid_seed() {
        const INVALID_SEED: &[u8] = b"invalid_seed";
        let crypto = EcvrfCrypto::new().unwrap();
        let proof = crypto.generate_proof(TEST_SEED).unwrap();
        let public_key = crypto.public_key().to_vec();
        let result = crypto.verify_proof(&public_key, proof.proof(), INVALID_SEED);
        assert!(result.is_err(), "Proof verification should fail");
    }

    #[test]
    fn test_get_public_key() {
        let crypto = EcvrfCrypto::new().unwrap();
        let public_key = crypto.public_key();
        assert_eq!(
            public_key,
            crypto.public_key.as_slice(),
            "Public key should match"
        );
        assert_eq!(public_key.len(), 65, "Public key should be 65 bytes");
    }
}
