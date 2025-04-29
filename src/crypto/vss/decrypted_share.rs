use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::crypto::{
    algebra::{self, Point, Scalar},
    keypair::{self, SecretKey},
    vss::{encrypted_share, EncryptedShares},
};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("Keypair error: {0}")]
    Keypair(#[from] keypair::Error),

    #[error("Algebra error: {0}")]
    Algebra(#[from] algebra::Error),

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

    pub fn from_scalars<I, T>(iter: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<Scalar>,
    {
        let mut shares = HashMap::new();
        let mut first = None;
        for (index, scalar) in iter.into_iter().enumerate() {
            let share: Scalar = scalar.into();

            if let Some(first) = &first {
                if !share.is_same_type(first) {
                    panic!("All shares must be of the same type");
                }
            } else {
                first = Some(share.clone());
            }

            shares.insert(index as u16 + 1, share);
        }
        Self(shares)
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

    pub fn verify(&self, index: &u16, commitments: Vec<Point>) -> Result<bool> {
        let share = self.get(index).ok_or(Error::ShareNotFound(*index))?;

        Ok(share.verify(*index, &commitments)?)
    }

    pub fn remove(&mut self, index: &u16) -> Result<Scalar> {
        self.0.remove(index).ok_or(Error::ShareNotFound(*index))
    }
}
