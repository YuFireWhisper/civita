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

type BanchingFactor = u16;
type KeyArray = [BanchingFactor; DEPTH];
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
    KadPayload(#[from] kad::payload::Error),

    #[error("{0}")]
    Encode(#[from] DecodeError),
}

#[derive(Debug)]
pub struct MerkleDag {
    transport: Arc<Transport>,
    root_hash: HashArray,
    nodes: HashMap<HashArray, Node>,
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

    pub async fn insert(&mut self, key: KeyArray, value: HashArray) -> Result<()> {
        let mut path = Vec::with_capacity(DEPTH);

        let root = self
            .nodes
            .remove(&self.root_hash)
            .expect("Root node should exist");

        path.push(root);

        for index in key.iter().take(DEPTH - 1) {
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

    async fn fetch_node(&self, hash: HashArray) -> Result<Node> {
        let key = kad::Key::ByHash(hash);

        self.transport
            .get_or_error(key)
            .await?
            .extract::<Node>(Variant::MerkleDagNode)
            .map_err(Error::from)
    }

    fn fill_nodes(&mut self, key: KeyArray, value: HashArray, mut path: Vec<Node>) {
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

        let indices: Vec<BanchingFactor> = key.into_iter().take(path.len()).collect();
        self.update_nodes(path, indices);
    }

    fn update_nodes(&mut self, mut path: Vec<Node>, indices: Vec<BanchingFactor>) {
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

    pub async fn get(&mut self, key: KeyArray) -> Option<HashArray> {
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

    async fn ensure_node_exists(&mut self, hash: HashArray) -> bool {
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

    pub async fn contains(&mut self, key: KeyArray) -> bool {
        let mut current = self.root_hash;

        for index in key.iter() {
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
        store::merkle_dag::{BanchingFactor, HashArray, KeyArray, MerkleDag, Node, DEPTH},
        MockTransport,
    };

    fn test_pair(key_val: BanchingFactor, value_val: u8) -> (KeyArray, HashArray) {
        let key = test_key(key_val);
        let value = test_value(value_val);

        (key, value)
    }

    fn test_key(key_val: BanchingFactor) -> KeyArray {
        let mut key = KeyArray::default();

        key[0] = key_val;
        key
    }

    fn test_value(value_val: u8) -> HashArray {
        let mut value = HashArray::default();

        value[0] = value_val;
        value
    }

    #[tokio::test]
    async fn true_after_insert() {
        const KEY_VAL: BanchingFactor = 1;
        const VALUE_VAL: u8 = 10;

        let transport = Arc::new(MockTransport::default());
        let mut dag = MerkleDag::new(transport);

        let (key, value) = test_pair(KEY_VAL, VALUE_VAL);

        dag.insert(key, value).await.unwrap();

        assert!(dag.contains(key).await);
    }

    #[tokio::test]
    async fn get_same_value_after_insert() {
        const KEY_VAL: BanchingFactor = 1;
        const VALUE_VAL: u8 = 10;

        let transport = Arc::new(MockTransport::default());
        let mut dag = MerkleDag::new(transport);

        let (key, value) = test_pair(KEY_VAL, VALUE_VAL);

        dag.insert(key, value).await.unwrap();

        let result = dag.get(key).await.unwrap();

        assert_eq!(result, value);
    }

    #[tokio::test]
    async fn empty_dag_returns_none_for_get() {
        const KEY_VAL: BanchingFactor = 1;

        let transport = Arc::new(MockTransport::default());
        let mut dag = MerkleDag::new(transport);

        let key = test_key(KEY_VAL);

        let result = dag.get(key).await;

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn nonexistent_key_returns_none() {
        const KEY_VAL: BanchingFactor = 1;
        const VALUE_VAL: u8 = 10;
        const NONEXISTENT_KEY: BanchingFactor = KEY_VAL + 1;

        let transport = Arc::new(MockTransport::default());
        let mut dag = MerkleDag::new(transport);

        let (key, value) = test_pair(KEY_VAL, VALUE_VAL);

        dag.insert(key, value).await.unwrap();

        let nonexistent_key: KeyArray = [NONEXISTENT_KEY; DEPTH];
        let result = dag.get(nonexistent_key).await;

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn insert_same_key_twice_updates_value() {
        const KEY_VAL: BanchingFactor = 1;
        const VALUE1_VAL: u8 = 10;
        const VALUE2_VAL: u8 = 20;

        let transport = Arc::new(MockTransport::default());
        let mut dag = MerkleDag::new(transport);

        let key = test_key(KEY_VAL);
        let value1 = test_value(VALUE1_VAL);
        let value2 = test_value(VALUE2_VAL);

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
        const VALUE: u8 = 42;

        let transport = Arc::new(MockTransport::default());
        let mut dag = MerkleDag::new(transport);

        let mut key = KeyArray::default();
        key.iter_mut().enumerate().for_each(|(i, byte)| {
            *byte = i as BanchingFactor;
        });

        let value = test_value(VALUE);

        dag.insert(key, value).await.unwrap();

        assert_eq!(dag.get(key).await.unwrap(), value);
        assert!(dag.contains(key).await);
    }

    #[tokio::test]
    async fn complex_tree_navigation_works() {
        const KEY_VAL1: BanchingFactor = 1;
        const KEY_VAL2: BanchingFactor = 2;
        const VALUE_VAL1: u8 = 10;
        const VALUE_VAL2: u8 = 20;

        let transport = Arc::new(MockTransport::default());
        let mut dag = MerkleDag::new(transport);

        let key1 = test_key(KEY_VAL1);
        let key2 = test_key(KEY_VAL2);

        let value1 = test_value(VALUE_VAL1);
        let value2 = test_value(VALUE_VAL2);

        dag.insert(key1, value1).await.unwrap();
        dag.insert(key2, value2).await.unwrap();

        assert_eq!(dag.get(key1).await.unwrap(), value1);
        assert_eq!(dag.get(key2).await.unwrap(), value2);
    }

    #[tokio::test]
    async fn transport_error_propagates_during_insert() {
        const ERROR_VAL: u8 = 42;
        const KEY_VAL: BanchingFactor = 1;
        const VALUE_VAL: u8 = 10;

        let mut transport = MockTransport::default();

        let error_hash = test_value(ERROR_VAL);
        transport
            .expect_get_or_error()
            .withf(move |key| matches!(key, Key::ByHash(hash) if hash == &error_hash))
            .returning(|_| Err(transport::Error::MockError));

        let mut root = Node::new();
        root.insert(KEY_VAL, error_hash);

        let transport = Arc::new(transport);
        let mut dag = MerkleDag::new_with_root(transport, root);

        let key = test_key(KEY_VAL);
        let value = test_value(VALUE_VAL);

        let result = dag.insert(key, value).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn failed_node_fetch_returns_false_for_contains() {
        const KEY_VAL: BanchingFactor = 1;

        let mut transport = MockTransport::default();

        transport
            .expect_get_or_error()
            .returning(|_| Err(transport::Error::MockError));

        let transport = Arc::new(transport);
        let mut dag = MerkleDag::new(transport);

        let key = test_key(KEY_VAL);

        assert!(!dag.contains(key).await);
    }

    #[tokio::test]
    async fn new_with_root_initializes_properly() {
        const KEY_VAL: BanchingFactor = 1;
        const VALUE_VAL: u8 = 10;

        let transport = Arc::new(MockTransport::default());
        let root = Node::new();
        let root_hash = root.hash();

        let mut dag = MerkleDag::new_with_root(transport, root);

        assert_eq!(dag.root_hash, root_hash);

        let (key, value) = test_pair(KEY_VAL, VALUE_VAL);

        dag.insert(key, value).await.unwrap();
        assert_eq!(dag.get(key).await.unwrap(), value);
    }

    #[tokio::test]
    async fn kad_payload_error_propagates() {
        const HASH_VAL: u8 = 42;
        const KEY_VAL: BanchingFactor = 1;
        const VALUE_VAL: u8 = 10;

        let mut transport = MockTransport::default();

        let hash = test_value(HASH_VAL);
        transport
            .expect_get_or_error()
            .withf(move |key| matches!(key, Key::ByHash(h) if h == &hash))
            .returning(|_| Ok(kad::Payload::MerkleDagNode(vec![2, 1, 2])));

        let mut root = Node::new();
        root.insert(KEY_VAL, hash);

        let transport = Arc::new(transport);
        let mut dag = MerkleDag::new_with_root(transport, root);

        let key = test_key(KEY_VAL);
        let value = test_value(VALUE_VAL);

        let result = dag.insert(key, value).await;
        assert!(
            matches!(result, Err(super::Error::KadPayload(_))),
            "Expected KadPayload error, got: {result:?}"
        );
    }
}
