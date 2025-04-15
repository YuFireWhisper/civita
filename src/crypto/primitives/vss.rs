use curv::{
    cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS,
    elliptic::curves::{secp256_k1::Secp256k1 as CurvSecp256k1, Scalar as CurvScalar},
};
use sha2::Sha256;

use crate::crypto::primitives::algebra::{Point, Scheme};

pub mod decrypted_share;
pub mod encrypted_share;

pub use decrypted_share::DecryptedShares;
pub use encrypted_share::EncryptedShares;

pub struct Vss;

impl Vss {
    pub fn share(
        scheme: &Scheme,
        threshold: u16,
        num_shares: u16,
    ) -> (DecryptedShares, Vec<Point>) {
        match scheme {
            Scheme::Secp256k1 => Self::generate_secp256k1(threshold, num_shares),
        }
    }

    fn generate_secp256k1(threshold: u16, num_shares: u16) -> (DecryptedShares, Vec<Point>) {
        let raw_secret = CurvScalar::<CurvSecp256k1>::random();
        let (vss, raw_shares) =
            VerifiableSS::<_, Sha256>::share(threshold, num_shares, &raw_secret);
        let derived_shares = DecryptedShares::from_scalars(raw_shares.iter().map(|s| s.to_owned()));
        let commitments = vss
            .commitments
            .into_iter()
            .map(Point::from)
            .collect::<Vec<Point>>();

        (derived_shares, commitments)
    }
}
