use crate::{
    crypto::{
        keypair::PublicKey,
        primitives::algebra::element::{Public, Secret},
    },
    MockError,
};
use std::{collections::HashMap, error::Error};

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

pub struct GenerateOutput<SK, PK>
where
    SK: Secret,
    PK: Public,
{
    pub secret: SK,
    pub public: PK,
    pub participants: Vec<libp2p::PeerId>,
}

#[async_trait::async_trait]
pub trait Dkg_<SK: Secret, PK: Public> {
    type Error: Error;

    async fn set_peers(
        &mut self,
        peers: HashMap<libp2p::PeerId, PublicKey>,
    ) -> Result<(), Self::Error>;
    async fn generate(&self, id: Vec<u8>) -> Result<GenerateOutput<SK, PK>, Self::Error>;
}
