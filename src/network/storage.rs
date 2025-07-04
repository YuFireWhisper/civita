use std::sync::Arc;

use libp2p::{kad::Event, Swarm};
use tokio::sync::Mutex;

use crate::{crypto::Multihash, network::behaviour::Behaviour, traits::Serializable};

mod network;

pub use network::Config as NetworkConfig;

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Network(#[from] network::Error),
}

pub enum Storage {
    Network(network::Storage),
}

impl Storage {
    pub fn new_network(swarm: Arc<Mutex<Swarm<Behaviour>>>, config: NetworkConfig) -> Self {
        Storage::Network(network::Storage::new(swarm, config))
    }

    pub(crate) fn handle_event(&self, event: Event) {
        match self {
            Storage::Network(storage) => storage.handle_event(event),
        }
    }

    pub async fn put<T>(&self, key: Multihash, value: T) -> Result<()>
    where
        T: Serializable + Send + Sync + 'static,
    {
        match self {
            Storage::Network(storage) => storage.put(key, value).await.map_err(Error::from),
        }
    }

    pub async fn put_batch<T, I>(&self, items: I) -> Result<()>
    where
        T: Serializable + Send + Sync + 'static,
        I: IntoIterator<Item = (Multihash, T)>,
    {
        match self {
            Storage::Network(storage) => storage.put_batch(items).await.map_err(Error::from),
        }
    }

    pub async fn get<T>(&self, key: &Multihash) -> Result<Option<T>>
    where
        T: Serializable + Send + Sync + 'static,
    {
        match self {
            Storage::Network(storage) => storage.get(key).await.map_err(Error::from),
        }
    }
}
