use crate::{
    crypto::Multihash,
    traits::{serializable, Serializable},
};

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Put(#[from] libp2p::kad::PutRecordError),

    #[error("{0}")]
    Get(#[from] libp2p::kad::GetRecordError),

    #[error("Waiting for Kademlia operation timed out after {0:?}")]
    Timeout(#[from] tokio::time::error::Elapsed),

    #[error("{0}")]
    Oneshot(#[from] tokio::sync::oneshot::error::RecvError),

    #[error("{0}")]
    Store(#[from] libp2p::kad::store::Error),

    #[error("{0}")]
    Serializable(#[from] serializable::Error),

    #[error("{0}")]
    Other(String),
}

#[async_trait::async_trait]
pub trait Storage: Clone + Send + Sync + 'static {
    async fn get<T>(&self, key: &Multihash) -> Result<Option<T>>
    where
        T: Serializable + Sync + Send + 'static;
    async fn put<T>(&mut self, key: Multihash, value: T) -> Result<()>
    where
        T: Serializable + Sync + Send + 'static;
    async fn put_batch<T, I>(&mut self, items: I) -> Result<()>
    where
        T: Serializable + Sync + Send + 'static,
        I: IntoIterator<Item = (Multihash, T)> + Send + Sync;
}
