use std::{collections::HashMap, sync::Arc};

use crate::network::transport::{
    self,
    protocols::kad::{self, payload::Variant},
};

#[cfg(not(test))]
use crate::network::transport::Transport;

#[cfg(test)]
use crate::network::transport::MockTransport as Transport;

pub mod node;

use bincode::error::DecodeError;
pub use node::Node;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Transport(#[from] transport::Error),

    #[error("{0}")]
    Kad(#[from] kad::Error),

    #[error("{0}")]
    KadPayload(#[from] kad::payload::Error),

    #[error("{0}")]
    Encode(#[from] DecodeError),
}

#[derive(Debug)]
pub struct MerkleDag {
    transport: Arc<Transport>,
    root_hash: [u8; 32],
    nodes: HashMap<[u8; 32], Node>,
}

impl MerkleDag {
    pub fn new(transport: Arc<Transport>) -> Self {
        let root = Node::new();

        Self::new_with_root(transport, root)
    }

    pub fn new_with_root(transport: Arc<Transport>, root: Node) -> Self {
        let mut nodes = HashMap::new();
        let root_hash = root.hash();
        nodes.insert(root_hash, root);

        Self {
            transport,
            root_hash,
            nodes,
        }
    }

    pub async fn insert(&mut self, key: [u8; 32], value: [u8; 32]) -> Result<()> {
        let mut path = Vec::with_capacity(32);

        let root = self
            .nodes
            .remove(&self.root_hash)
            .expect("Root node should exist");

        path.push(root);

        for index in key.iter().take(31) {
            let current = path.last().expect("Path should not be empty");

            let child_hash = match current.child(index) {
                Some(child) => child,
                None => break,
            };

            let child = match self.nodes.remove(child_hash) {
                Some(child) => child,
                None => self.fetch_node(*child_hash).await?,
            };

            path.push(child);
        }

        self.fill_nodes(key, value, path);

        Ok(())
    }

    async fn fetch_node(&self, hash: [u8; 32]) -> Result<Node> {
        let key = kad::Key::ByHash(hash);
        self.transport
            .get_or_error(key)
            .await?
            .extract::<Node>(Variant::MerkleDagNode)
            .map_err(Error::from)
    }

    fn fill_nodes(&mut self, key: [u8; 32], value: [u8; 32], mut path: Vec<Node>) {
        let mut child_hash = value;

        for index in key.iter().rev().take(32 - path.len()) {
            let mut node = Node::new();
            node.insert(*index, child_hash);

            let hash = node.hash();
            child_hash = hash;
            self.nodes.insert(hash, node);
        }

        let node = path.last_mut().expect("Path should not be empty");
        node.insert(key[31], child_hash);

        let key = key.into_iter().take(path.len() - 1).collect::<Vec<_>>();
        self.update_nodes(path, key);
    }

    fn update_nodes(&mut self, mut path: Vec<Node>, key: Vec<u8>) {
        for index in key.into_iter().take(31).rev() {
            let node = path.pop().expect("Path should not be empty");
            let node_hash = node.hash();

            self.nodes.insert(node_hash, node);

            if let Some(parent) = path.last_mut() {
                parent.insert(index, node_hash);
            }
        }

        let hash = path.last().expect("Path should not be empty").hash();

        self.root_hash = hash;
        self.nodes
            .insert(hash, path.pop().expect("Path should not be empty"));
    }

    pub async fn get(&mut self, key: [u8; 32]) -> Option<[u8; 32]> {
        let mut current = self.root_hash;

        for index in key.iter() {
            if !self.ensure_node_exists(current).await {
                return None;
            }

            let node = self.nodes.get(&current).expect("Node should exist");

            match node.child(index) {
                Some(child) => current = *child,
                None => return None,
            }
        }

        Some(current)
    }

    async fn ensure_node_exists(&mut self, hash: [u8; 32]) -> bool {
        if self.nodes.contains_key(&hash) {
            return true;
        }

        let node = match self.fetch_node(hash).await {
            Ok(node) => node,
            Err(_) => return false,
        };

        self.nodes.insert(hash, node);
        true
    }

    pub async fn contains(&mut self, value: [u8; 32]) -> bool {
        let mut current = self.root_hash;

        for index in value.iter() {
            if !self.ensure_node_exists(current).await {
                return false;
            }

            let node = self.nodes.get(&current).expect("Node should exist");

            match node.child(index) {
                Some(child) => current = *child,
                None => return false,
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::network::transport::{store::merkle_dag::MerkleDag, MockTransport};

    #[tokio::test]
    async fn success_insert() {
        let transport = Arc::new(MockTransport::default());
        let mut dag = MerkleDag::new(transport);

        let key = [0u8; 32];
        let value = [1u8; 32];

        dag.insert(key, value).await.unwrap();

        assert!(dag.contains(key).await);
    }

    #[tokio::test]
    async fn success_get() {
        let transport = Arc::new(MockTransport::default());
        let mut dag = MerkleDag::new(transport);

        let key = [0u8; 32];
        let value = [1u8; 32];

        dag.insert(key, value).await.unwrap();

        let result = dag.get(key).await.unwrap();

        assert_eq!(result, value);
    }
}
