pub mod decrypted_share;
pub mod encrypted_share;

pub use decrypted_share::DecryptedShares;
pub use encrypted_share::EncryptedShares;

use crate::crypto::primitives::algebra::{Point, Scalar};

pub trait Vss: Send + Sync {
    type Error: std::error::Error;

    fn share(
        secret: &Scalar,
        threshold: u16,
        num_shares: u16,
    ) -> Result<(DecryptedShares, Vec<Point>), Self::Error>;
    fn verify(index: &u16, share: &Scalar, commitments: &[Point]) -> bool;
    fn reconstruct(shares: &[(u16, Scalar)], threshold: u16) -> Result<Scalar, Self::Error>;
}
