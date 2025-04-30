use std::collections::HashSet;

use crate::{
    crypto::{
        algebra::{Point, Scalar},
        keypair::PublicKey,
    },
    mocks::MockError,
    utils::IndexedMap,
};

pub mod joint_feldman;

pub use joint_feldman::JointFeldman;

#[mockall::automock(type Error=MockError;)]
#[async_trait::async_trait]
pub trait Dkg: Send + Sync {
    type Error: std::error::Error;

    async fn set_peers(
        &self,
        peers: IndexedMap<libp2p::PeerId, PublicKey>,
    ) -> Result<(), Self::Error>;
    async fn generate(&self, id: Vec<u8>) -> Result<GenerateResult, Self::Error>;
}

pub enum GenerateResult {
    Success {
        secret: Scalar,
        partial_publics: IndexedMap<libp2p::PeerId, Vec<Point>>,
    },
    Failure {
        invalid_peers: HashSet<libp2p::PeerId>,
    },
}
