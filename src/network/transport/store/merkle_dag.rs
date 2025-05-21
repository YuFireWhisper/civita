use std::sync::Arc;

use bincode::error::DecodeError;

use crate::network::transport::{
    self,
    protocols::kad::{self, payload::Variant},
};

#[cfg(not(test))]
use crate::network::transport::Transport;

#[cfg(test)]
use crate::network::transport::MockTransport as Transport;

pub mod node;

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
    root: Node,
}

impl MerkleDag {
    pub fn new(transport: Arc<Transport>) -> Self {
        let root = Node::new();

        Self::new_with_root(transport, root)
    }

    pub fn new_with_root(transport: Arc<Transport>, root: Node) -> Self {
        Self { transport, root }
    }

    pub async fn insert(&mut self, key: KeyArray, value: HashArray) -> Result<()> {
        let transport = self.transport.clone();
        let mut current = &mut self.root;

        for (depth, &index) in key.iter().enumerate() {
            if depth == DEPTH - 1 {
                let value_node = Node::new_with_hash(value);
                current.insert(index, value_node);
                break;
            }

            if let Some(child) = current.child_mut(&index) {
                if child.children().is_empty() {
                    let mut node = Self::fetch_node(&transport, child.hash()).await?;
                    child.insert_with_iter(node.children_take());
                }
            }

            current = current.children_mut().entry(index).or_default();
        }

        self.root.update_hash();

        Ok(())
    }

    async fn fetch_node(transport: &Arc<Transport>, hash: HashArray) -> Result<Node> {
        Ok(transport
            .get_or_error(kad::Key::ByHash(hash))
            .await?
            .extract::<Node>(Variant::MerkleDagNode)?)
    }

    pub async fn get(&mut self, key: KeyArray) -> Option<HashArray> {
        let mut current = &mut self.root;

        for (depth, &index) in key.iter().enumerate() {
            if let Some(child) = current.child_mut(&index) {
                if child.children().is_empty() && depth != DEPTH - 1 {
                    let mut node = Self::fetch_node(&self.transport, child.hash())
                        .await
                        .expect("Node should exist");
                    child.children_mut().extend(node.children_take());
                }
                current = child;
            } else {
                return None;
            }
        }

        Some(current.hash())
    }

    pub async fn contains(&mut self, key: KeyArray) -> bool {
        let mut current = &mut self.root;

        for (depth, &index) in key.iter().enumerate() {
            if let Some(child) = current.child_mut(&index) {
                if child.children().is_empty() && depth != DEPTH - 1 {
                    let mut node = Self::fetch_node(&self.transport, child.hash())
                        .await
                        .expect("Node should exist");
                    child.children_mut().extend(node.children_take());
                }
                current = child;
            } else {
                return false;
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
        let error_node = Node::new_with_hash(error_hash);
        root.insert(KEY_VAL, error_node);

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

        assert_eq!(dag.root.hash(), root_hash);

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
        let hash_node = Node::new_with_hash(hash);
        root.insert(KEY_VAL, hash_node);

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
