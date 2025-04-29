use std::collections::HashSet;

use crate::{
    crypto::{
        algebra::{Point, Scalar},
        index_map::IndexedMap,
        keypair::PublicKey,
    },
    mocks::MockError,
};

pub mod joint_feldman;

pub use joint_feldman::JointFeldman;

#[mockall::automock(type Error=MockError;)]
#[async_trait::async_trait]
pub trait Dkg {
    type Error: std::error::Error;

    async fn set_peers(
        &mut self,
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
