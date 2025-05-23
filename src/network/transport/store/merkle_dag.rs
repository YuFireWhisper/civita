use std::sync::Arc;

use bincode::error::DecodeError;

use crate::network::transport::{
    self,
    protocols::kad::{self},
};

#[cfg(not(test))]
use crate::network::transport::Transport;

#[cfg(test)]
use crate::network::transport::MockTransport as Transport;

pub mod node;

pub use node::Node;

type Result<T> = std::result::Result<T, Error>;

type BanchingFactor = u16;
pub type KeyArray = [BanchingFactor; DEPTH];
type HashArray = [u8; 32];

const DEPTH: usize = 16;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Transport(#[from] transport::Error),

    #[error("{0}")]
    Kad(#[from] kad::Error),

    #[error("{0}")]
    Encode(#[from] DecodeError),

    #[error("{0}")]
    Node(#[from] node::Error),
}

#[derive(Debug)]
pub struct MerkleDag {
    transport: Arc<Transport>,
    root: Arc<Node>,
    batch_size: usize,
}

impl MerkleDag {
    pub fn new(transport: Arc<Transport>, batch_size: usize) -> Self {
        let root = Node::new();
        Self::new_with_root(transport, root, batch_size)
    }

    pub fn new_with_root(transport: Arc<Transport>, root: Node, batch_size: usize) -> Self {
        let root = Arc::new(root);

        MerkleDag {
            transport,
            root,
            batch_size,
        }
    }

    pub async fn insert(&mut self, key: KeyArray, value: HashArray) -> Result<()> {
        self.root
            .insert(key, value, &self.transport)
            .await
            .map_err(Error::from)
    }

    pub async fn batch_insert(&mut self, pairs: Vec<(KeyArray, HashArray)>) -> Result<()> {
        self.root
            .batch_insert(pairs, &self.transport, self.batch_size)
            .await
            .map_err(Error::from)
    }

    pub async fn get(&mut self, key: KeyArray) -> Result<Option<HashArray>> {
        self.root
            .get(key, &self.transport)
            .await
            .map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {}
