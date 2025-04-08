use crate::crypto::core::element::{Public, Secret};
use std::error::Error;

pub struct Shares<SK, PK>
where
    SK: Secret,
    PK: Public,
{
    pub shares: Vec<SK>,
    pub commitments: Vec<PK>,
}

pub trait Vss<SK, PK>
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
