use std::{collections::HashMap, error::Error};

use crate::crypto::primitives::algebra::element::{Public, Secret};

pub struct Shares {
    pub shares: HashMap<u16, Vec<u8>>,
    pub commitments: Vec<Vec<u8>>,
}

pub trait Vss<SK, PK>: Send + Sync + Send
where
    SK: Secret,
    PK: Public,
{
    type Error: Error;

    fn share(secret: &SK, threshold: u16, num_shares: u16) -> Result<Shares, Self::Error>;
    fn verify(index: &u16, share: &SK, commitments: &[PK]) -> bool;
    fn reconstruct(shares: &[(u16, SK)], threshold: u16) -> Result<SK, Self::Error>;
}
