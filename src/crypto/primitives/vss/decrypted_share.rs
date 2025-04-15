use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::crypto::{
    keypair::{self, SecretKey},
    primitives::{
        algebra::element::{self, Point, Scalar},
        vss::{
            encrypted_share::{self, EncryptedShares},
            Vss,
        },
    },
};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("Keypair error: {0}")]
    Keypair(#[from] keypair::Error),

    #[error("Element error: {0}")]
    Element(#[from] element::Error),

    #[error("Encrypted share error: {0}")]
    EncryptedShare(#[from] encrypted_share::Error),

    #[error("Share not found for index: {0}")]
    ShareNotFound(u16),
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Serialize, Deserialize)]
#[derive(PartialEq, Eq)]
pub struct DecryptedShares(HashMap<u16, Scalar>);

impl DecryptedShares {
    pub fn empty() -> Self {
        Self(HashMap::new())
    }

    pub fn from_encrypted(
        encrypted_shares: &EncryptedShares,
        secret_key: &SecretKey,
    ) -> Result<Self> {
        let mut decrypted_shares = HashMap::new();

        for (index, encrypted_share) in encrypted_shares.iter() {
            let decrypted_share = encrypted_share.to_scalar(secret_key)?;
            decrypted_shares.insert(index, decrypted_share);
        }

        Ok(DecryptedShares(decrypted_shares))
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

    pub fn get(&self, index: &u16) -> Option<&Scalar> {
        self.0.get(index)
    }

    pub fn iter(&self) -> impl Iterator<Item = (u16, &Scalar)> {
        self.0.iter().map(|(k, v)| (*k, v))
    }

    pub fn verify<V: Vss>(&self, index: &u16, commitments: Vec<Point>) -> Result<bool> {
        let share = self.get(index).ok_or(Error::ShareNotFound(*index))?;

        Ok(V::verify(index, share, &commitments))
    }

    pub fn remove(&mut self, index: &u16) -> Result<Scalar> {
        self.0.remove(index).ok_or(Error::ShareNotFound(*index))
    }
}
