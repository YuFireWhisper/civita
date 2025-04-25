use bincode::{Decode, Encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::keypair::PublicKey;

const RESIDENT_ID_SIZE: usize = 32;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("Invalid key length, expected {RESIDENT_ID_SIZE}, got {0}")]
    InvalidLength(usize),
}

#[derive(Clone, Copy)]
#[derive(Debug)]
#[derive(Encode, Decode)]
#[derive(Hash)]
#[derive(PartialEq, Eq)]
#[derive(PartialOrd, Ord)]
#[derive(Serialize, Deserialize)]
pub struct ResidentId([u8; RESIDENT_ID_SIZE]);

impl ResidentId {
    pub fn from_public_key(key: &PublicKey) -> Self {
        Self::from(key)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Self::try_from(bytes)
    }

    pub fn from_array(array: [u8; RESIDENT_ID_SIZE]) -> Self {
        Self::from(array)
    }

    pub fn random() -> Self {
        let bytes = rand::random::<[u8; RESIDENT_ID_SIZE]>();
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; RESIDENT_ID_SIZE] {
        self.as_ref()
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.into()
    }

    pub fn to_array(&self) -> [u8; RESIDENT_ID_SIZE] {
        self.into()
    }
}

impl From<&PublicKey> for ResidentId {
    fn from(key: &PublicKey) -> Self {
        let hash = Sha256::digest(key.as_bytes());
        Self(hash.into())
    }
}

impl TryFrom<&[u8]> for ResidentId {
    type Error = Error;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        if value.len() != RESIDENT_ID_SIZE {
            return Err(Error::InvalidLength(value.len()));
        }

        let mut id = [0; RESIDENT_ID_SIZE];
        id.copy_from_slice(value);
        Ok(Self(id))
    }
}

impl From<[u8; RESIDENT_ID_SIZE]> for ResidentId {
    fn from(array: [u8; RESIDENT_ID_SIZE]) -> Self {
        Self(array)
    }
}

impl From<&ResidentId> for Vec<u8> {
    fn from(resident_id: &ResidentId) -> Self {
        resident_id.0.to_vec()
    }
}

impl From<&ResidentId> for [u8; RESIDENT_ID_SIZE] {
    fn from(resident_id: &ResidentId) -> Self {
        resident_id.0
    }
}

impl AsRef<[u8; RESIDENT_ID_SIZE]> for ResidentId {
    fn as_ref(&self) -> &[u8; RESIDENT_ID_SIZE] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::keypair;

    use super::*;

    const INVALID_LENGTH_SMALL: usize = 16;
    const INVALID_LENGTH_LARGE: usize = 64;

    fn create_test_bytes() -> [u8; RESIDENT_ID_SIZE] {
        let mut bytes = [0u8; RESIDENT_ID_SIZE];
        (0..RESIDENT_ID_SIZE).for_each(|i| {
            bytes[i] = i as u8;
        });
        bytes
    }

    #[test]
    fn create_from_public_key_returns_expected_hash() {
        let (_, pub_key) = keypair::generate_secp256k1();

        let expected_hash = Sha256::digest(pub_key.as_bytes());
        let expected_id = ResidentId::from_array(expected_hash.into());

        let resident_id = ResidentId::from_public_key(&pub_key);
        assert_eq!(resident_id, expected_id);
    }

    #[test]
    fn from_bytes_with_valid_length_succeeds() {
        let bytes = create_test_bytes();
        let result = ResidentId::from_bytes(&bytes);

        assert!(result.is_ok());
        let resident_id = result.unwrap();
        assert_eq!(resident_id.as_bytes(), &bytes);
    }

    #[test]
    fn from_bytes_with_invalid_length_returns_error() {
        let short_bytes = vec![0u8; INVALID_LENGTH_SMALL];
        let result = ResidentId::from_bytes(&short_bytes);

        assert!(result.is_err());
        if let Err(Error::InvalidLength(len)) = result {
            assert_eq!(len, INVALID_LENGTH_SMALL);
        } else {
            panic!("Expected InvalidLength error");
        }

        let long_bytes = vec![0u8; INVALID_LENGTH_LARGE];
        let result = ResidentId::from_bytes(&long_bytes);

        assert!(result.is_err());
        if let Err(Error::InvalidLength(len)) = result {
            assert_eq!(len, INVALID_LENGTH_LARGE);
        } else {
            panic!("Expected InvalidLength error");
        }
    }

    #[test]
    fn random_generates_unique_ids() {
        let id1 = ResidentId::random();
        let id2 = ResidentId::random();

        assert_ne!(id1, id2);
    }

    #[test]
    fn conversion_methods_preserve_data_integrity() {
        let original_bytes = create_test_bytes();
        let resident_id = ResidentId::from_array(original_bytes);

        assert_eq!(resident_id.as_bytes(), &original_bytes);

        let vec_bytes: Vec<u8> = (&resident_id).into();
        assert_eq!(vec_bytes, original_bytes.to_vec());

        let array_bytes: [u8; RESIDENT_ID_SIZE] = (&resident_id).into();
        assert_eq!(array_bytes, original_bytes);
    }

    #[test]
    fn when_same_public_key_used_creates_identical_resident_ids() {
        let (_, pub_key) = keypair::generate_secp256k1();

        let id1 = ResidentId::from_public_key(&pub_key);
        let id2 = ResidentId::from_public_key(&pub_key);

        assert_eq!(id1, id2);
    }

    #[test]
    fn when_different_public_keys_used_creates_different_resident_ids() {
        let (_, pub_key1) = keypair::generate_secp256k1();
        let (_, pub_key2) = keypair::generate_secp256k1();

        let id1 = ResidentId::from_public_key(&pub_key1);
        let id2 = ResidentId::from_public_key(&pub_key2);

        assert_ne!(id1, id2);
    }

    #[test]
    fn should_create_same_id_when_using_equivalent_constructors() {
        let bytes = create_test_bytes();

        let id1 = ResidentId::from_array(bytes);
        let id2 = ResidentId::from_bytes(&bytes).unwrap();
        let id3 = ResidentId::try_from(&bytes[..]).unwrap();

        assert_eq!(id1, id2);
        assert_eq!(id2, id3);
    }

    #[test]
    fn should_implement_ordering_correctly() {
        let id1 = ResidentId::from_array([1u8; RESIDENT_ID_SIZE]);
        let id2 = ResidentId::from_array([2u8; RESIDENT_ID_SIZE]);

        assert!(id1 < id2);
        assert!(id2 > id1);
        assert_ne!(id1, id2);
    }

    #[test]
    fn hash_trait_implementation() {
        use std::collections::HashSet;

        let id1 = ResidentId::random();
        let id2 = ResidentId::from_array(id1.to_array());
        let id3 = ResidentId::random();

        let mut set = HashSet::new();
        set.insert(id1);

        assert!(set.contains(&id2));
        assert!(!set.contains(&id3));
    }
}
