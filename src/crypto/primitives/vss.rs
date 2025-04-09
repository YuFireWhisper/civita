use std::error::Error;

use crate::crypto::primitives::algebra::element::{Public, Secret};

pub trait Vss<SK, PK>: Send + Sync + Send
where
    SK: Secret,
    PK: Public,
{
    type Error: Error;

    fn share(
        secret: &SK,
        threshold: u16,
        num_shares: u16,
    ) -> Result<(Vec<SK>, Vec<PK>), Self::Error>;
    fn verify(index: &u16, share: &SK, commitments: &[PK]) -> bool;
    fn reconstruct(shares: &[(u16, SK)], threshold: u16) -> Result<SK, Self::Error>;
}
