use std::{collections::HashMap, error::Error};

use serde::{Deserialize, Serialize};

use crate::crypto::{
    keypair::{self, SecretKey},
    primitives::algebra::element::{Public, Secret},
};

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum SharesError {
    #[error("Share not found for peer index: {0}")]
    ShareNotFound(u16),

    #[error("Keypair error: {0}")]
    Keypair(#[from] keypair::Error),
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(PartialEq, Eq)]
#[derive(Serialize, Deserialize)]
pub struct Shares {
    pub shares: HashMap<u16, Vec<u8>>,
    pub commitments: Vec<Vec<u8>>,
}

pub trait Vss<SK, PK>: Send + Sync
where
    SK: Secret,
    PK: Public,
{
    type Error: Error;

    fn share(secret: &SK, threshold: u16, num_shares: u16) -> Result<Shares, Self::Error>;
    fn verify(index: &u16, share: &SK, commitments: &[PK]) -> bool;
    fn reconstruct(shares: &[(u16, SK)], threshold: u16) -> Result<SK, Self::Error>;
}

impl Shares {
    pub fn empty() -> Self {
        Self {
            shares: HashMap::new(),
            commitments: Vec::new(),
        }
    }

    pub fn verify<SK: Secret, PK: Public, V: Vss<SK, PK>>(
        &self,
        index: &u16,
        secret_key: &SecretKey,
    ) -> Result<bool, SharesError> {
        let encrypted_share = self
            .shares
            .get(index)
            .ok_or(SharesError::ShareNotFound(*index))?;
        let decrypted_share = secret_key.decrypt(encrypted_share)?;
        let share = SK::from_bytes(&decrypted_share);
        let commitments = self
            .commitments
            .iter()
            .map(|c| PK::from_bytes(c))
            .collect::<Vec<_>>();

        Ok(V::verify(index, &share, &commitments))
    }
}
