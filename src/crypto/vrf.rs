pub mod dvrf;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use dvrf::{crypto, messager, processes};
use libp2p::gossipsub::MessageId;
use libp2p::identity;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Crypto(#[from] crypto::Error),
    #[error("{0}")]
    Messager(#[from] messager::Error),
    #[error("{0}")]
    Processes(#[from] processes::Error),
    #[error("Timeout waiting for VRF process: {0}")]
    Timeout(MessageId),
    #[error("Process not found: {0}")]
    ProcessNotFound(MessageId),
    #[error("Process failed: {0}")]
    ProcessFailed(MessageId),
    #[error("Failed to verify VRF proof")]
    VerifyVrfProof,
    #[error("PeerId parsing error: {0}")]
    PeerId(#[from] identity::ParseError),
    #[error("Message ID not available")]
    MessageId,
    #[error("Failed to get source peer ID")]
    SourcePeerId,
    #[error("Process error: {0}")]
    Process(String),
}

pub trait Vrf: Send + Sync {
    fn new_random(self: Arc<Self>)
        -> Pin<Box<dyn Future<Output = Result<[u8; 32], Error>> + Send>>;
}

pub trait VrfCallback: Send + Sync {
    fn set_result_callback<F>(&self, callback: F)
    where
        F: Fn(MessageId, &[u8]) + Send + Sync + 'static;
    fn set_failure_callback<F>(&self, callback: F)
    where
        F: Fn(MessageId) + Send + Sync + 'static;
}

pub trait VrfFactory: Send + Sync {
    fn create_vrf(
        &mut self,
    ) -> impl Future<Output = Result<Arc<dyn Vrf>, Error>> + Send;
}
