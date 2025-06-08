use std::{
    collections::{HashMap, HashSet},
    mem,
    sync::Arc,
};

use bincode::error::DecodeError;

use crate::{
    constants::HashArray,
    network::transport::{
        self,
        protocols::kad::{self},
    },
};

#[cfg(not(test))]
use crate::network::transport::Transport;

#[cfg(test)]
use crate::network::transport::MockTransport as Transport;

pub mod node;

pub use node::Node;

type BanchingFactor = u16;
type KeyArray = [BanchingFactor; DEPTH];
type Result<T> = std::result::Result<T, Error>;

const DEPTH: usize = 16;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Transport(#[from] transport::Error),

    #[error("{0}")]
    Kad(#[from] kad::Error),

    #[error("{0}")]
    Decode(#[from] DecodeError),
}

#[derive(Debug)]
pub struct MerkleDag {
    transport: Arc<Transport>,
    root: Node,
}

impl MerkleDag {
    pub fn new(transport: Arc<Transport>) -> Self {
        let root = Node::default();
        MerkleDag { transport, root }
    }

    pub fn new_with_root(transport: Arc<Transport>, root: Node) -> Self {
        MerkleDag { transport, root }
    }

    pub async fn insert(&self, key: HashArray, value: HashArray) -> Result<HashSet<HashArray>> {
        self.root
            .insert(hash_to_key(key), value, &self.transport)
            .await
    }

    pub async fn batch_insert<I>(&self, iter: I) -> Result<HashSet<HashArray>>
    where
        I: IntoIterator<Item = (HashArray, HashArray)>,
    {
        self.root
            .batch_insert(
                iter.into_iter().map(|(k, v)| (hash_to_key(k), v)),
                &self.transport,
            )
            .await
    }

    pub async fn get(&self, key: HashArray) -> Result<Option<HashArray>> {
        self.root.get(hash_to_key(key), &self.transport).await
    }

    pub async fn batch_get<I>(&self, iter: I) -> Result<HashMap<HashArray, HashArray>>
    where
        I: IntoIterator<Item = HashArray>,
    {
        self.root
            .batch_get(iter.into_iter().map(hash_to_key), &self.transport)
            .await
            .map(|map| map.into_iter().map(|(k, v)| (key_to_hash(k), v)).collect())
    }

    pub fn root(&self) -> &Node {
        &self.root
    }
}

fn hash_to_key(hash: HashArray) -> KeyArray {
    unsafe { mem::transmute::<HashArray, KeyArray>(hash) }
}

fn key_to_hash(key: KeyArray) -> HashArray {
    unsafe { mem::transmute::<KeyArray, HashArray>(key) }
}

#[cfg(test)]
mod tests {}
