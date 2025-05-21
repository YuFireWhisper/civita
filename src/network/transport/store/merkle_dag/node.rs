use std::collections::HashMap;

use bincode::error::DecodeError;
use dashmap::{
    mapref::one::{Ref, RefMut},
    DashMap,
};
use futures::{stream::FuturesUnordered, StreamExt};
use serde::Deserialize;
use tokio::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard};

use crate::network::transport::{
    self,
    protocols::kad::{self, payload::Variant},
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
    KadPayload(#[from] kad::payload::Error),

    #[error("{0}")]
    Encode(#[from] DecodeError),

    #[error("{0}")]
    Poison(String),

    #[error("Child node does not have a hash")]
    ChildNodeHash,
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
                        let fetched_node = Self::fetch_node(transport, hash).await?;
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

    async fn fetch_node(transport: &Transport, hash: HashArray) -> Result<Node> {
        Ok(transport
            .get_or_error(kad::Key::ByHash(hash))
            .await?
            .extract::<Node>(Variant::MerkleDagNode)?)
    }

    pub async fn batch_insert(
        &self,
        pairs: Vec<(KeyArray, HashArray)>,
        transport: &Transport,
        batch_size: usize,
    ) -> Result<()> {
        let mut futures = FuturesUnordered::new();

        for chunk in pairs.chunks(batch_size) {
            for (key, value) in chunk {
                futures.push(self.insert(*key, *value, transport));
            }

            while let Some(result) = futures.next().await {
                result?;
            }
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

        if let Some(mut child) = self.child_mut(&key[depth]) {
            let child = child.value_mut();

            if let Some(hash) = child.hash().await {
                let lock = child.lock_fetch_lock().await;

                if child.children.is_empty() {
                    let fetched_node = Self::fetch_node(transport, hash).await?;
                    drop(lock);
                    child.children = fetched_node.children;
                }
            }

            return Box::pin(child.get_inner(depth + 1, key, transport)).await;
        }

        Ok(None)
    }

    pub async fn update_hash(&self) {
        if self.children.is_empty() {
            return;
        }

        for child in self.children.iter() {
            if child.value().hash_read().await.is_none() {
                Box::pin(child.value().update_hash()).await;
            }
        }

        let bytes = self.to_vec().await;
        let hash = blake3::hash(&bytes);

        self.hash.write().await.replace(hash.into());
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
        let mut entries = self.children.iter().collect::<Vec<_>>();
        entries.sort_by(|a, b| a.key().cmp(b.key()));

        let mut bytes = Vec::with_capacity(entries.len() * BASE_SIZE);

        for entry in entries {
            let child_hash = entry
                .value()
                .hash()
                .await
                .expect("Child node does not have a hash");
            let mut index_bytes = [0u8; INDEX_SIZE];
            index_bytes.copy_from_slice(&entry.key().to_be_bytes());
            bytes.extend_from_slice(&index_bytes);
            bytes.extend_from_slice(&child_hash);
        }

        bytes
    }
}

impl TryFrom<Vec<u8>> for Node {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        Self::try_from(bytes.as_slice())
    }
}

impl TryFrom<&[u8]> for Node {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        bincode::serde::decode_from_slice(bytes, bincode::config::standard())
            .map(|(node, _)| node)
            .map_err(Error::from)
    }
}

impl<'de> Deserialize<'de> for Node {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;

        if bytes.len() % BASE_SIZE != 0 {
            return Err(serde::de::Error::custom("Invalid byte length"));
        }

        let children = DashMap::with_capacity(bytes.len() / BASE_SIZE);

        for chunk in bytes.chunks_exact(BASE_SIZE) {
            let index_bytes = std::array::from_fn(|i| chunk[i]);
            let index = BanchingFactor::from_be_bytes(index_bytes);
            let child_hash: HashArray = chunk[INDEX_SIZE..]
                .try_into()
                .map_err(|_| serde::de::Error::custom("Failed to convert slice to array"))?;
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
    use super::*;

    const KEY_1: KeyArray = [1; DEPTH];
    const HASH_1: HashArray = [1; HASH_SIZE];

    #[tokio::test]
    async fn new_node_is_empty() {
        let node = Node::new();

        assert!(node.hash().await.is_none());
        assert!(node.children.is_empty());
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
    async fn returns_some_after_insert() {
        let root = Node::new();
        let transport = Transport::default();

        root.insert(KEY_1, HASH_1, &transport).await.unwrap();

        let result = root.get(KEY_1, &transport).await.unwrap();

        assert_eq!(result, Some(HASH_1));
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
}
