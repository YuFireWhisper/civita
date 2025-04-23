use crate::{
    crypto::{
        index_map::IndexedMap,
        keypair::PublicKey,
        primitives::algebra::{Point, Scalar},
    },
    MockError,
};
use std::{collections::HashSet, error::Error};

use mockall::automock;

pub mod joint_feldman;

pub enum GenerateResult {
    Success {
        secret: Scalar,
        partial_publics: IndexedMap<libp2p::PeerId, Vec<Point>>,
    },
    Failure {
        invalid_peers: HashSet<libp2p::PeerId>,
    },
}

#[automock(type Error=MockError;)]
#[async_trait::async_trait]
pub trait Dkg_ {
    type Error: Error;

    async fn set_peers(
        &mut self,
        peers: IndexedMap<libp2p::PeerId, PublicKey>,
    ) -> Result<(), Self::Error>;
    async fn generate(&self, id: Vec<u8>) -> Result<GenerateResult, Self::Error>;
}
