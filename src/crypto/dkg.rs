use crate::{
    crypto::{
        index_map::IndexedMap,
        keypair::PublicKey,
        primitives::algebra::{Point, Scalar},
    },
    MockError,
};
use std::{
    collections::HashSet,
    error::Error,
};

use async_trait::async_trait;
use mockall::automock;

pub mod classic;
pub mod joint_feldman;
pub mod signature;

pub use signature::{Data, Scheme};

#[automock(type Error=MockError;)]
pub trait Dkg: Send + Sync {
    type Error: Error;

    fn sign(&self, seed: &[u8], msg: &[u8]) -> Data;
    fn validate(&self, msg: &[u8], sig: &Data) -> bool;
    fn aggregate(&self, indices: &[u16], sigs: Vec<Data>) -> Result<Data, Self::Error>;
}

#[automock(type Dkg=MockDkg; type Error=MockError;)]
#[async_trait]
pub trait DkgFactory {
    type Error: Error;
    type Dkg: Dkg;

    async fn create(&self) -> Result<Self::Dkg, Self::Error>;
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
