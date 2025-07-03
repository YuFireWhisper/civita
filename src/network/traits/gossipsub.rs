use libp2p::gossipsub::{PublishError, SubscriptionError};
use tokio::sync::mpsc;

use crate::{network::traits::storage, traits::serializable};

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Serializable(#[from] serializable::Error),

    #[error("{0}")]
    Storage(#[from] storage::Error),

    #[error("{0}")]
    Subscribe(#[from] SubscriptionError),

    #[error("{0}")]
    Publish(#[from] PublishError),
}

#[async_trait::async_trait]
pub trait Gossipsub: Clone + Send + Sync + 'static {
    async fn subscribe(&self, topic: u8) -> Result<mpsc::Receiver<Vec<u8>>>;
    async fn unsubscribe(&self, topic: u8) -> Result<()>;
    async fn publish(&self, topic: u8, data: Vec<u8>) -> Result<()>;
}
