use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::crypto::{
    keypair::{self, PublicKey, SecretKey},
    primitives::{
        algebra::{self, Scalar},
        vss::decrypted_share::DecryptedShares,
    },
};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("Keypair error: {0}")]
    Keypair(#[from] keypair::Error),

    #[error("Algebra error: {0}")]
    Algebra(#[from] algebra::Error),

    #[error("Share not found for index: {0}")]
    ShareNotFound(u16),
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Serialize, Deserialize)]
#[derive(PartialEq, Eq)]
pub struct EncryptedShare(Vec<u8>);

#[derive(Clone)]
#[derive(Debug)]
#[derive(Serialize, Deserialize)]
#[derive(PartialEq, Eq)]
pub struct EncryptedShares(HashMap<u16, EncryptedShare>);

impl EncryptedShare {
    pub fn new(encrypted_share: Vec<u8>) -> Self {
        Self(encrypted_share)
    }

    pub fn from_scalar(scalar: &Scalar, public_key: &PublicKey) -> Result<Self> {
        let encrypted_share = public_key.encrypt(&scalar.to_vec()?)?;
        Ok(Self(encrypted_share))
    }

    pub fn to_scalar(&self, secret_key: &SecretKey) -> Result<Scalar> {
        let decrypted_share = secret_key.decrypt(&self.0)?;
        Scalar::from_slice(&decrypted_share).map_err(Error::from)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl EncryptedShares {
    pub fn empty() -> Self {
        Self(HashMap::new())
    }

    pub fn from_decrypted<'a>(
        decrypted_shares: &DecryptedShares,
        public_keys: impl Iterator<Item = (u16, &'a PublicKey)>,
    ) -> Result<Self> {
        let mut encrypted_shares = HashMap::new();
        let mut public_keys_len = 0;

        for (index, public_key) in public_keys {
            assert!(index > 0, "Index must be greater than 0, because it is 1-based");
            // let index = index - 1;
            let share = decrypted_shares
                .get(&index)
                .ok_or(Error::ShareNotFound(index))?;

            let encrypted_share = EncryptedShare::from_scalar(share, public_key)?;
            encrypted_shares.insert(index, encrypted_share);
            public_keys_len += 1;
        }

        assert_eq!(
            public_keys_len,
            decrypted_shares.len(),
            "Number of public keys must match the number of shares"
        );

        Ok(EncryptedShares(encrypted_shares))
    }

    pub fn len(&self) -> u16 {
        self.0
            .len()
            .try_into()
            .expect("unreachable: length is too large")
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn get(&self, index: &u16) -> Option<&EncryptedShare> {
        self.0.get(index)
    }

    pub fn iter(&self) -> impl Iterator<Item = (u16, &EncryptedShare)> {
        self.0.iter().map(|(k, v)| (*k, v))
    }
}
