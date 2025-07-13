use std::sync::Arc;

use civita_serialize::Serialize;
use libp2p::{kad::Event, Swarm};
use tokio::sync::Mutex;

use crate::{crypto::Multihash, network::behaviour::Behaviour};

mod local_multi;
mod local_one;
mod network;

pub use network::Config as NetworkConfig;

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Network(#[from] network::Error),

    #[error("{0}")]
    LocalOne(#[from] local_one::Error),
}

pub enum Storage {
    Network(network::Storage),
    LocalOne(local_one::Storage),
    LocalMulti(local_multi::Storage),
}

impl Storage {
    pub fn new_network(swarm: Arc<Mutex<Swarm<Behaviour>>>, config: NetworkConfig) -> Self {
        Storage::Network(network::Storage::new(swarm, config))
    }

    pub fn new_local_one() -> Self {
        Storage::LocalOne(local_one::Storage::new())
    }

    pub fn new_local_multi(core: Arc<local_one::Storage>) -> Self {
        Storage::LocalMulti(local_multi::Storage::new(core))
    }

    pub(crate) fn handle_event(&self, event: Event) {
        if let Storage::Network(storage) = self {
            storage.handle_event(event);
        }
    }

    pub async fn put<T>(&self, key: Multihash, value: T) -> Result<()>
    where
        T: Serialize + Send + Sync + 'static,
    {
        match self {
            Storage::Network(storage) => storage.put(key, value).await.map_err(Error::from),
            Storage::LocalOne(storage) => storage.put(key, value).map_err(Error::from),
            Storage::LocalMulti(storage) => storage.put(key, value).map_err(Error::from),
        }
    }

    pub async fn put_batch<T, I>(&self, items: I) -> Result<()>
    where
        T: Serialize + Send + Sync + 'static,
        I: IntoIterator<Item = (Multihash, T)>,
    {
        match self {
            Storage::Network(storage) => storage.put_batch(items).await.map_err(Error::from),
            Storage::LocalOne(storage) => storage.put_batch(items).map_err(Error::from),
            Storage::LocalMulti(storage) => storage.put_batch(items).map_err(Error::from),
        }
    }

    pub async fn get<T>(&self, key: &Multihash) -> Result<Option<T>>
    where
        T: Serialize + Send + Sync + 'static,
    {
        match self {
            Storage::Network(storage) => storage.get(key).await.map_err(Error::from),
            Storage::LocalOne(storage) => storage.get(key).map_err(Error::from),
            Storage::LocalMulti(storage) => storage.get(key).map_err(Error::from),
        }
    }
}
