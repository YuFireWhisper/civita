use crate::MockError;
use std::error::Error;

use async_trait::async_trait;
use mockall::automock;

pub mod classic;
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
