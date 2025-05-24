use std::{collections::HashMap, thread};

use dashmap::{
    mapref::one::{Ref, RefMut},
    DashMap, DashSet,
};
use futures::{stream::FuturesUnordered, StreamExt};
use tokio::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard};

use crate::network::transport::{
    self,
    protocols::kad,
    store::merkle_dag::{BanchingFactor, HashArray, KeyArray, DEPTH},
};

#[cfg(not(test))]
use crate::network::transport::Transport;

#[cfg(test)]
use crate::network::transport::MockTransport as Transport;

type Result<T> = std::result::Result<T, Error>;

const INDEX_SIZE: usize = std::mem::size_of::<BanchingFactor>();
const HASH_SIZE: usize = std::mem::size_of::<HashArray>();
const BASE_SIZE: usize = INDEX_SIZE + HASH_SIZE;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Transport(#[from] transport::Error),

    #[error("{0}")]
    Kad(#[from] kad::Error),

    #[error("{0}")]
    IO(#[from] std::io::Error),

    #[error("Invalid Byte Length")]
    InvalidByteLength,

    #[error("Invalid kad payload")]
    InvalidKadPayload,
}

#[derive(Debug)]
#[derive(Default)]
pub struct Node {
    hash: RwLock<Option<HashArray>>,
    children: DashMap<BanchingFactor, Node>,
    fetch_lock: Mutex<()>,
}

impl Node {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_with_hash(hash: HashArray) -> Self {
        Self {
            hash: RwLock::new(Some(hash)),
            ..Default::default()
        }
    }

    pub fn new_with_children(children: HashMap<BanchingFactor, Node>) -> Self {
        Self {
            children: children.into_iter().collect(),
            ..Default::default()
        }
    }

    pub async fn insert(
        &self,
        key: KeyArray,
        value: HashArray,
        transport: &Transport,
    ) -> Result<()> {
        self.insert_inner(0, key, value, transport).await
    }

    async fn insert_inner(
        &self,
        depth: usize,
        key: KeyArray,
        value: HashArray,
        transport: &Transport,
    ) -> Result<()> {
        self.clear_hash().await;

        if depth == DEPTH - 1 {
            let new = Node::new_with_hash(value);
            self.children.insert(key[depth], new);
            return Ok(());
        }

        match self.child_mut(&key[depth]) {
            Some(mut child) => {
                let child = child.value_mut();

                if let Some(hash) = child.hash().await {
                    let lock = child.lock_fetch_lock().await;

                    if child.children.is_empty() {
                        let fetched_node = Self::fetch_node(transport, &hash).await?;
                        drop(lock);
                        child.children = fetched_node.children;
                    }
                }

                return Box::pin(child.insert_inner(depth + 1, key, value, transport)).await;
            }
            None => {
                let new = Node::new();
                Box::pin(new.insert_inner(depth + 1, key, value, transport)).await?;
                self.children.insert(key[depth], new);
            }
        }

        Ok(())
    }

    async fn lock_fetch_lock(&self) -> MutexGuard<()> {
        self.fetch_lock.lock().await
    }

    async fn fetch_node(transport: &Transport, hash: &HashArray) -> Result<Node> {
        transport
            .get_or_error::<Node>(hash)
            .await
            .map_err(Error::from)
    }

    pub async fn batch_insert(
        &self,
        pairs: Vec<(KeyArray, HashArray)>,
        transport: &Transport,
        batch_size: usize,
    ) -> Result<()> {
        let mut grouped: HashMap<BanchingFactor, Vec<(KeyArray, HashArray)>> = HashMap::new();

        for (key, value) in pairs {
            grouped.entry(key[0]).or_default().push((key, value));
        }

        let mut futures = FuturesUnordered::new();
        let max_concurrent = thread::available_parallelism()?.get() * 2;

        for (_, group) in grouped {
            for chunk in group.chunks(batch_size) {
                if futures.len() >= max_concurrent {
                    if let Some(result) = futures.next().await {
                        result?;
                    }
                }

                for (key, value) in chunk {
                    futures.push(self.insert(*key, *value, transport));
                }
            }
        }

        while let Some(result) = futures.next().await {
            result?;
        }

        Ok(())
    }

    pub async fn get(&self, key: KeyArray, transport: &Transport) -> Result<Option<HashArray>> {
        self.get_inner(0, key, transport).await
    }

    async fn get_inner(
        &self,
        depth: usize,
        key: KeyArray,
        transport: &Transport,
    ) -> Result<Option<HashArray>> {
        if depth == DEPTH - 1 {
            return Ok(match self.child(&key[depth]) {
                Some(child) => child.value().hash().await,
                None => None,
            });
        }

        if let Some(child_ref) = self.child(&key[depth]) {
            let child = child_ref.value();

            if let Some(hash) = child.hash().await {
                if child.children.is_empty() {
                    let lock = child.lock_fetch_lock().await;
                    if child.children.is_empty() {
                        let fetched_node = Self::fetch_node(transport, &hash).await?;
                        drop(lock);
                        for (idx, node) in fetched_node.children.into_iter() {
                            child.children.insert(idx, node);
                        }
                    } else {
                        drop(lock);
                    }
                }
            }

            return Box::pin(child.get_inner(depth + 1, key, transport)).await;
        }

        Ok(None)
    }

    pub async fn update_hash(&self) -> DashSet<HashArray> {
        if self.children.is_empty() {
            return DashSet::new();
        }

        let mut updated = DashSet::new();

        for child in self.children.iter() {
            if child.value().hash_read().await.is_none() {
                updated.extend(Box::pin(child.value().update_hash()).await);
            }
        }

        let bytes = self.to_vec().await;
        let hash = blake3::hash(&bytes);

        updated.insert(hash.into());
        self.hash.write().await.replace(hash.into());

        updated
    }

    async fn hash_read(&self) -> RwLockReadGuard<Option<HashArray>> {
        self.hash.read().await
    }

    pub async fn hash(&self) -> Option<HashArray> {
        *self.hash_read().await
    }

    pub async fn clear_hash(&self) {
        self.hash.write().await.take();
    }

    pub fn child(&self, index: &BanchingFactor) -> Option<Ref<BanchingFactor, Node>> {
        self.children.get(index)
    }

    pub fn child_mut(&self, index: &BanchingFactor) -> Option<RefMut<BanchingFactor, Node>> {
        self.children.get_mut(index)
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        Self::try_from(slice)
    }

    pub async fn to_vec(&self) -> Vec<u8> {
        let mut entries = Vec::with_capacity(self.children.len());

        for entry in self.children.iter() {
            entries.push((
                *entry.key(),
                entry
                    .value()
                    .hash()
                    .await
                    .expect("Child node does not have a hash"),
            ));
        }

        entries.sort_by_key(|(key, _)| *key);

        let mut bytes = Vec::with_capacity(entries.len() * BASE_SIZE);
        for (key, hash) in entries {
            bytes.extend_from_slice(&key.to_be_bytes());
            bytes.extend_from_slice(&hash);
        }

        bytes
    }
}

impl Clone for Node {
    fn clone(&self) -> Self {
        Node {
            hash: RwLock::new(None),
            children: self.children.clone(),
            fetch_lock: Mutex::new(()),
        }
    }
}

impl TryFrom<Vec<u8>> for Node {
    type Error = Error;

    fn try_from(vec: Vec<u8>) -> Result<Self> {
        Self::try_from(vec.as_slice())
    }
}

impl TryFrom<&[u8]> for Node {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self> {
        if slice.is_empty() {
            return Ok(Node::default());
        }

        if slice.len() % BASE_SIZE != 0 {
            return Err(Error::InvalidByteLength);
        }

        let children = DashMap::with_capacity(slice.len() / BASE_SIZE);

        for chunk in slice.chunks_exact(BASE_SIZE) {
            let index_bytes = std::array::from_fn(|i| chunk[i]);
            let index = BanchingFactor::from_be_bytes(index_bytes);
            let child_hash: HashArray = chunk[INDEX_SIZE..]
                .try_into()
                .map_err(|_| Error::InvalidByteLength)?;
            let child = Node::new_with_hash(child_hash);
            children.insert(index, child);
        }

        Ok(Node {
            children,
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    const KEY_1: KeyArray = [1; DEPTH];
    const KEY_2: KeyArray = [2; DEPTH];
    const HASH_1: HashArray = [1; HASH_SIZE];
    const HASH_2: HashArray = [2; HASH_SIZE];

    fn create_error_transport() -> Transport {
        let mut transport = Transport::default();
        transport
            .expect_get_or_error::<Vec<u8>>()
            .returning(|_| Err(transport::Error::MockError));
        transport
    }

    #[tokio::test]
    async fn new_node_is_empty() {
        let node = Node::new();

        assert!(node.hash().await.is_none());
        assert!(node.children.is_empty());
    }

    #[tokio::test]
    async fn new_with_hash_initializes_correctly() {
        let node = Node::new_with_hash(HASH_1);

        assert_eq!(node.hash().await, Some(HASH_1));
        assert!(node.children.is_empty());
    }

    #[tokio::test]
    async fn new_with_children_initializes_correctly() {
        let mut children = HashMap::new();
        children.insert(1, Node::new_with_hash(HASH_1));
        children.insert(2, Node::new_with_hash(HASH_2));

        let node = Node::new_with_children(children);

        assert!(node.hash().await.is_none());
        assert_eq!(node.children.len(), 2);
        assert_eq!(node.child(&1).unwrap().value().hash().await, Some(HASH_1));
        assert_eq!(node.child(&2).unwrap().value().hash().await, Some(HASH_2));
    }

    #[tokio::test]
    async fn insert_adds_child() {
        let root = Node::new();
        let transport = Transport::default();

        let result = root.insert(KEY_1, HASH_1, &transport).await;

        assert!(result.is_ok());
        assert_eq!(root.children.len(), 1);
    }

    #[tokio::test]
    async fn insert_multiple_keys_adds_multiple_children() {
        let root = Node::new();
        let transport = Transport::default();

        root.insert(KEY_1, HASH_1, &transport).await.unwrap();
        root.insert(KEY_2, HASH_2, &transport).await.unwrap();

        assert_eq!(root.children.len(), 2);
        let result1 = root.get(KEY_1, &transport).await.unwrap();
        let result2 = root.get(KEY_2, &transport).await.unwrap();

        assert_eq!(result1, Some(HASH_1));
        assert_eq!(result2, Some(HASH_2));
    }

    #[tokio::test]
    async fn insert_overwrites_existing_value() {
        let root = Node::new();
        let transport = Transport::default();
        let new_hash: HashArray = [3; HASH_SIZE];

        root.insert(KEY_1, HASH_1, &transport).await.unwrap();
        root.insert(KEY_1, new_hash, &transport).await.unwrap();

        let result = root.get(KEY_1, &transport).await.unwrap();

        assert_eq!(result, Some(new_hash));
    }

    #[tokio::test]
    async fn insert_clears_parent_hash() {
        let root = Node::new();
        let transport = Transport::default();

        *root.hash.write().await = Some(HASH_1);

        root.insert(KEY_1, HASH_1, &transport).await.unwrap();

        assert!(root.hash().await.is_none());
    }

    #[tokio::test]
    async fn insert_with_transport_error_fails() {
        let root = Node::new();
        let transport = create_error_transport();

        root.children.insert(KEY_1[0], Node::new_with_hash(HASH_1));

        let result = root.insert(KEY_1, HASH_2, &transport).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Transport(_)));
    }

    #[tokio::test]
    async fn batch_insert_adds_multiple_values() {
        let root = Node::new();
        let transport = Transport::default();

        let pairs = vec![(KEY_1, HASH_1), (KEY_2, HASH_2)];

        let result = root.batch_insert(pairs, &transport, 1).await;

        assert!(result.is_ok());
        assert_eq!(root.get(KEY_1, &transport).await.unwrap(), Some(HASH_1));
        assert_eq!(root.get(KEY_2, &transport).await.unwrap(), Some(HASH_2));
    }

    #[tokio::test]
    async fn batch_insert_with_transport_error_fails() {
        let root = Node::new();
        let transport = create_error_transport();

        root.children.insert(KEY_1[0], Node::new_with_hash(HASH_1));

        let pairs = vec![(KEY_1, HASH_2)];

        let result = root.batch_insert(pairs, &transport, 1).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Transport(_)));
    }

    #[tokio::test]
    async fn batch_insert_respects_batch_size() {
        let root = Node::new();
        let transport = Transport::default();

        let mut pairs = Vec::new();
        for i in 0..10 {
            let mut key = [0; DEPTH];
            key[0] = i as BanchingFactor;
            pairs.push((key, HASH_1));
        }

        let result = root.batch_insert(pairs, &transport, 5).await;

        assert!(result.is_ok());
        assert_eq!(root.children.len(), 10);
    }

    #[tokio::test]
    async fn get_returns_none_for_nonexistent_key() {
        let root = Node::new();
        let transport = Transport::default();

        let result = root.get(KEY_1, &transport).await.unwrap();

        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn get_returns_value_after_insert() {
        let root = Node::new();
        let transport = Transport::default();

        root.insert(KEY_1, HASH_1, &transport).await.unwrap();

        let result = root.get(KEY_1, &transport).await.unwrap();

        assert_eq!(result, Some(HASH_1));
    }

    #[tokio::test]
    async fn get_with_transport_error_fails() {
        let root = Node::new();
        let transport = create_error_transport();

        root.children.insert(KEY_1[0], Node::new_with_hash(HASH_1));

        let result = root.get(KEY_1, &transport).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Transport(_)));
    }

    #[tokio::test]
    async fn update_hash_with_no_children_does_nothing() {
        let node = Node::new();

        let updated = node.update_hash().await;

        assert!(node.hash().await.is_none());
        assert!(updated.is_empty());
    }

    #[tokio::test]
    async fn update_hash_with_children_calculates_hash() {
        let node = Node::new();
        let transport = Transport::default();

        node.insert(KEY_1, HASH_1, &transport).await.unwrap();
        node.insert(KEY_2, HASH_2, &transport).await.unwrap();

        let updated = node.update_hash().await;

        assert!(node.hash().await.is_some());
        assert_eq!(updated.len(), (DEPTH * 2) - 1); // -1 for the root node
    }

    #[tokio::test]
    async fn hash_returns_consistent_value() {
        let root = Node::new();
        let transport = Transport::default();

        root.insert(KEY_1, HASH_1, &transport).await.unwrap();
        root.update_hash().await;

        let hash1 = root.hash().await;
        let hash2 = root.hash().await;

        assert!(hash1.is_some());
        assert!(hash2.is_some());
        assert_eq!(hash1, hash2);
    }

    #[tokio::test]
    async fn clear_hash_removes_hash() {
        let node = Node::new_with_hash(HASH_1);

        node.clear_hash().await;

        assert!(node.hash().await.is_none());
    }

    #[tokio::test]
    async fn update_hash_recursively_updates_children() {
        let root = Node::new();
        let child = Node::new();
        let grandchild = Node::new();

        grandchild.children.insert(1, Node::new_with_hash(HASH_1));
        child.children.insert(1, grandchild);
        root.children.insert(1, child);

        root.update_hash().await;

        assert!(root.hash().await.is_some());
        assert!(root.child(&1).unwrap().value().hash().await.is_some());
        assert!(root
            .child(&1)
            .unwrap()
            .value()
            .child(&1)
            .unwrap()
            .value()
            .hash()
            .await
            .is_some());
    }

    #[tokio::test]
    async fn serialize_and_deserialize() {
        let node = Node::new();
        node.children.insert(0, Node::new_with_hash(HASH_1));
        node.children.insert(1, Node::new_with_hash(HASH_1));

        node.update_hash().await;

        let serialized = node.to_vec().await;
        let deserialized = Node::from_slice(&serialized).expect("Failed to deserialize");

        deserialized.update_hash().await;

        assert!(deserialized.hash().await.is_some());
        assert_eq!(node.hash().await, deserialized.hash().await);
        assert_eq!(node.children.len(), deserialized.children.len());
    }

    #[tokio::test]
    async fn deserialize_invalid_data_fails() {
        let invalid_data = vec![1, 2, 3];

        let result = Node::from_slice(&invalid_data);

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn serialize_empty_node_gives_empty_vector() {
        let node = Node::new();

        let serialized = node.to_vec().await;

        assert!(serialized.is_empty());
    }

    #[tokio::test]
    async fn serialize_order_is_consistent() {
        let node1 = Node::new();
        let node2 = Node::new();

        node1.children.insert(1, Node::new_with_hash(HASH_1));
        node1.children.insert(2, Node::new_with_hash(HASH_2));

        node2.children.insert(2, Node::new_with_hash(HASH_2));
        node2.children.insert(1, Node::new_with_hash(HASH_1));

        let serialized1 = node1.to_vec().await;
        let serialized2 = node2.to_vec().await;

        assert_eq!(serialized1, serialized2);
    }

    #[tokio::test]
    async fn fetch_lock_prevents_concurrent_fetches() {
        let node = Node::new();

        let lock1 = node.lock_fetch_lock().await;

        let lock_future = node.lock_fetch_lock();
        let timeout_result = tokio::time::timeout(Duration::from_millis(100), lock_future).await;

        assert!(timeout_result.is_err());

        drop(lock1);

        let _lock2 = tokio::time::timeout(Duration::from_millis(100), node.lock_fetch_lock())
            .await
            .expect("Failed to acquire lock after previous was released");
    }
}
