pub mod dvrf;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use dvrf::{crypto, messager, processes};
use libp2p::gossipsub::MessageId;
use libp2p::identity;
use mockall::automock;
use thiserror::Error;

use crate::network::transport::libp2p_transport::protocols;
use crate::MockError;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Crypto(#[from] crypto::Error),
    #[error("{0}")]
    Messager(String),
    #[error("{0}")]
    Processes(#[from] processes::Error),
    #[error("{0}")]
    Gossipsub(#[from] protocols::gossipsub::message::Error),
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
    #[error("Process error: {0}")]
    Process(String),
    #[error("Invalid message type")]
    InvalidMessageType,
    #[error("Invalid payload")]
    InvalidPayload,
}

impl From<messager::Error> for Error {
    fn from(err: messager::Error) -> Self {
        Error::Messager(err.to_string())
    }
}

#[automock]
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

#[automock(type E=MockError; type V=MockVrf;)]
pub trait VrfFactory: Send + Sync {
    type E: std::error::Error;
    type V: Vrf;

    fn create(&mut self) -> impl Future<Output = Result<Arc<Self::V>, Self::E>> + Send;
}
