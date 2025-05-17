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

        for index in key.iter().skip(path.len()).rev() {
            let mut node = Node::new();
            node.insert(*index, child_hash);

            let hash = node.hash();
            child_hash = hash;
            self.nodes.insert(hash, node);
        }

        if !path.is_empty() {
            let last_index = path.len() - 1;
            let node = path.last_mut().expect("Path should not be empty");
            node.insert(key[last_index], child_hash);
        }

        let indices: Vec<u8> = key.into_iter().take(path.len()).collect();
        self.update_nodes(path, indices);
    }

    fn update_nodes(&mut self, mut path: Vec<Node>, indices: Vec<u8>) {
        for index in indices.into_iter().rev().skip(1) {
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

    use crate::network::transport::{
        self,
        protocols::kad::{self, Key},
        store::merkle_dag::{MerkleDag, Node},
        MockTransport,
    };

    fn test_pair(key_val: u8, value_val: u8) -> ([u8; 32], [u8; 32]) {
        let mut key = [0u8; 32];
        let mut value = [0u8; 32];

        key[0] = key_val;
        value[0] = value_val;

        (key, value)
    }

    #[tokio::test]
    async fn true_after_insert() {
        let transport = Arc::new(MockTransport::default());
        let mut dag = MerkleDag::new(transport);

        let key = [0u8; 32];
        let value = [1u8; 32];

        dag.insert(key, value).await.unwrap();

        assert!(dag.contains(key).await);
    }

    #[tokio::test]
    async fn get_same_value_after_insert() {
        let transport = Arc::new(MockTransport::default());
        let mut dag = MerkleDag::new(transport);

        let key = [0u8; 32];
        let value = [1u8; 32];

        dag.insert(key, value).await.unwrap();

        let result = dag.get(key).await.unwrap();

        assert_eq!(result, value);
    }

    #[tokio::test]
    async fn empty_dag_returns_none_for_get() {
        let transport = Arc::new(MockTransport::default());
        let mut dag = MerkleDag::new(transport);

        let key = [0u8; 32];

        let result = dag.get(key).await;

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn nonexistent_key_returns_none() {
        let transport = Arc::new(MockTransport::default());
        let mut dag = MerkleDag::new(transport);

        let key = [0u8; 32];
        let value = [1u8; 32];

        dag.insert(key, value).await.unwrap();

        let nonexistent_key = [2u8; 32];
        let result = dag.get(nonexistent_key).await;

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn insert_same_key_twice_updates_value() {
        let transport = Arc::new(MockTransport::default());
        let mut dag = MerkleDag::new(transport);

        let key = [0u8; 32];
        let value1 = [1u8; 32];
        let value2 = [2u8; 32];

        dag.insert(key, value1).await.unwrap();
        assert_eq!(dag.get(key).await.unwrap(), value1);

        dag.insert(key, value2).await.unwrap();

        assert_eq!(dag.get(key).await.unwrap(), value2);
    }

    #[tokio::test]
    async fn multiple_inserts_maintain_structure() {
        let transport = Arc::new(MockTransport::default());
        let mut dag = MerkleDag::new(transport);

        let (key1, value1) = test_pair(1, 10);
        let (key2, value2) = test_pair(2, 20);
        let (key3, value3) = test_pair(3, 30);

        dag.insert(key1, value1).await.unwrap();
        dag.insert(key2, value2).await.unwrap();
        dag.insert(key3, value3).await.unwrap();

        assert_eq!(dag.get(key1).await.unwrap(), value1);
        assert_eq!(dag.get(key2).await.unwrap(), value2);
        assert_eq!(dag.get(key3).await.unwrap(), value3);
    }

    #[tokio::test]
    async fn deep_path_creation_works() {
        let transport = Arc::new(MockTransport::default());
        let mut dag = MerkleDag::new(transport);

        let mut key = [0u8; 32];
        key.iter_mut().enumerate().for_each(|(i, byte)| {
            *byte = i as u8;
        });

        let value = [0xFF; 32];

        dag.insert(key, value).await.unwrap();

        assert_eq!(dag.get(key).await.unwrap(), value);
        assert!(dag.contains(key).await);
    }

    #[tokio::test]
    async fn complex_tree_navigation_works() {
        let transport = Arc::new(MockTransport::default());
        let mut dag = MerkleDag::new(transport);

        let mut key1 = [0u8; 32];
        let mut key2 = [0u8; 32];

        key1[15] = 1;
        key2[15] = 2;

        let value1 = [1u8; 32];
        let value2 = [2u8; 32];

        dag.insert(key1, value1).await.unwrap();
        dag.insert(key2, value2).await.unwrap();

        assert_eq!(dag.get(key1).await.unwrap(), value1);
        assert_eq!(dag.get(key2).await.unwrap(), value2);
    }

    #[tokio::test]
    async fn transport_error_propagates_during_insert() {
        let mut transport = MockTransport::default();

        let error_hash = [0xAA; 32];
        transport
            .expect_get_or_error()
            .withf(move |key| matches!(key, Key::ByHash(hash) if hash == &error_hash))
            .returning(|_| Err(transport::Error::MockError));

        let mut root = Node::new();
        root.insert(1, error_hash);

        let transport = Arc::new(transport);
        let mut dag = MerkleDag::new_with_root(transport, root);

        let mut key = [0u8; 32];
        key[0] = 1;

        let result = dag.insert(key, [0u8; 32]).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn failed_node_fetch_returns_false_for_contains() {
        let mut transport = MockTransport::default();

        transport
            .expect_get_or_error()
            .returning(|_| Err(transport::Error::MockError));

        let transport = Arc::new(transport);
        let mut dag = MerkleDag::new(transport);

        assert!(!dag.contains([0xBB; 32]).await);
    }

    #[tokio::test]
    async fn new_with_root_initializes_properly() {
        let transport = Arc::new(MockTransport::default());
        let root = Node::new();
        let root_hash = root.hash();

        let mut dag = MerkleDag::new_with_root(transport, root);

        assert_eq!(dag.root_hash, root_hash);

        let key = [0u8; 32];
        let value = [1u8; 32];

        dag.insert(key, value).await.unwrap();
        assert_eq!(dag.get(key).await.unwrap(), value);
    }

    #[tokio::test]
    async fn kad_payload_error_propagates() {
        let mut transport = MockTransport::default();

        let hash = [0xCC; 32];
        transport
            .expect_get_or_error()
            .withf(move |key| matches!(key, Key::ByHash(h) if h == &hash))
            .returning(|_| Ok(kad::Payload::MerkleDagNode(vec![2, 1, 2])));

        let mut root = Node::new();
        root.insert(1, hash);

        let transport = Arc::new(transport);
        let mut dag = MerkleDag::new_with_root(transport, root);

        let mut key = [0u8; 32];
        key[0] = 1;

        let result = dag.insert(key, [0u8; 32]).await;
        assert!(
            matches!(result, Err(super::Error::KadPayload(_))),
            "Expected KadPayload error, got: {result:?}"
        );
    }
}
