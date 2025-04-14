use std::{collections::HashMap, error::Error};

use serde::{Deserialize, Serialize};

use crate::crypto::{
    keypair::{self, SecretKey},
    primitives::algebra::element::{self, Point, Scalar},
};

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum SharesError {
    #[error("Share not found for peer index: {0}")]
    ShareNotFound(u16),

    #[error("Keypair error: {0}")]
    Keypair(#[from] keypair::Error),

    #[error("Element error: {0}")]
    Element(#[from] element::Error),
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(PartialEq, Eq)]
#[derive(Serialize, Deserialize)]
pub struct Shares {
    pub shares: HashMap<u16, Vec<u8>>,
    pub commitments: Vec<Vec<u8>>,
}

pub trait Vss: Send + Sync {
    type Error: Error;

    fn share(secret: &Scalar, threshold: u16, num_shares: u16) -> Result<Shares, Self::Error>;
    fn verify(index: &u16, share: &Scalar, commitments: &[Point]) -> bool;
    fn reconstruct(shares: &[(u16, Scalar)], threshold: u16) -> Result<Scalar, Self::Error>;
}

impl Shares {
    pub fn empty() -> Self {
        Self {
            shares: HashMap::new(),
            commitments: Vec::new(),
        }
    }

    pub fn verify<V: Vss>(&self, index: &u16, secret_key: &SecretKey) -> Result<bool, SharesError> {
        let encrypted_share = self
            .shares
            .get(index)
            .ok_or(SharesError::ShareNotFound(*index))?;
        let decrypted_share = secret_key.decrypt(encrypted_share)?;
        let share = Scalar::from_slice(&decrypted_share)?;
        let commitments = self
            .commitments
            .iter()
            .map(|c| Point::from_slice(c))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(V::verify(index, &share, &commitments))
    }
}
