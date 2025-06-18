use std::collections::{HashMap, HashSet};

use crossbeam_skiplist::{map::Entry, SkipMap};
use futures::{
    stream::{self, FuturesUnordered},
    StreamExt,
};
use generic_array::GenericArray;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::{
    crypto::{traits::hasher::HashArray, Hasher},
    network::transport::store::merkle_dag::{Error, HasherConfig, KeyArray, Result},
};

#[cfg(not(test))]
use crate::network::transport::Transport;

#[cfg(test)]
use crate::network::transport::MockTransport as Transport;

type ChildrenMap<H> = SkipMap<<H as HasherConfig>::BanchingFactor, Node<H>>;

pub struct Node<H: HasherConfig> {
    hash: RwLock<HashArray<H>>,
    children: ChildrenMap<H>,
}

impl<H: HasherConfig> Node<H> {
    pub fn with_hash(hash: HashArray<H>) -> Self {
        Node {
            hash: RwLock::new(hash),
            ..Default::default()
        }
    }

    pub async fn with_children(children: ChildrenMap<H>) -> Self {
        Node {
            hash: RwLock::new(calc_hash(&children).await),
            children,
        }
    }

    pub async fn insert(
        &self,
        key_hash: HashArray<H>,
        value: HashArray<H>,
        transport: &Transport,
    ) -> Result<HashSet<HashArray<H>>> {
        self.insert_inner(H::convert_to_key(key_hash), value, transport, 0)
            .await
    }

    async fn insert_inner(
        &self,
        key: KeyArray<H>,
        value: HashArray<H>,
        transport: &Transport,
        depth: usize,
    ) -> Result<HashSet<HashArray<H>>> {
        if Self::is_last_stub(depth) {
            self.children.insert(key[depth], Node::with_hash(value));
            return Ok(HashSet::from([self.recalc_hash().await]));
        }

        let entry = self
            .child_with_ensure_loaded(&key[depth], depth, transport)
            .await?;

        let mut changed =
            Box::pin(entry.value().insert_inner(key, value, transport, depth + 1)).await?;

        changed.insert(self.recalc_hash().await);

        Ok(changed)
    }

    fn is_last_stub(depth: usize) -> bool {
        depth == H::DEPTH - 1
    }

    async fn child_with_ensure_loaded(
        &self,
        index: &H::BanchingFactor,
        depth: usize,
        transport: &Transport,
    ) -> Result<Entry<H::BanchingFactor, Node<H>>> {
        match self.children.get(index) {
            Some(entry) => {
                entry.value().ensure_loaded(depth, transport).await?;
                Ok(entry)
            }
            None => {
                self.children.insert(*index, Node::default());
                Ok(self.children.get(index).unwrap())
            }
        }
    }

    async fn ensure_loaded(&self, depth: usize, transport: &Transport) -> Result<()> {
        if self.is_missing(depth).await {
            let fetched = transport
                .get_or_error::<Node<H>, H>(&self.hash().await)
                .await?;
            self.children.clear();
            fetched.children.into_iter().for_each(|(index, child)| {
                self.children.insert(index, child);
            });
        }

        Ok(())
    }

    async fn is_missing(&self, depth: usize) -> bool {
        !self.is_leaf(depth)
            && self.children.is_empty()
            && *self.hash.read().await == HashArray::<H>::default()
    }

    fn is_leaf(&self, depth: usize) -> bool {
        depth == H::DEPTH
    }

    async fn recalc_hash(&self) -> HashArray<H> {
        if self.children.is_empty() {
            return HashArray::<H>::default();
        }

        let new_hash = calc_hash(&self.children).await;
        *self.hash.write().await = new_hash.clone();
        new_hash
    }

    pub async fn batch_insert<I>(
        &self,
        iter: I,
        transport: &Transport,
    ) -> Result<HashSet<HashArray<H>>>
    where
        I: IntoIterator<Item = (HashArray<H>, HashArray<H>)>,
    {
        self.batch_insert_inner(
            iter.into_iter().map(|(k, v)| (H::convert_to_key(k), v)),
            transport,
            0,
        )
        .await
    }

    async fn batch_insert_inner<I>(
        &self,
        iter: I,
        transport: &Transport,
        depth: usize,
    ) -> Result<HashSet<HashArray<H>>>
    where
        I: IntoIterator<Item = (KeyArray<H>, HashArray<H>)>,
    {
        if Self::is_last_stub(depth) {
            iter.into_iter().for_each(|(key, value)| {
                self.children.insert(key[depth], Node::with_hash(value));
            });
            return Ok(HashSet::from([self.recalc_hash().await]));
        }

        let grouped: HashMap<_, Vec<_>> =
            iter.into_iter()
                .fold(HashMap::new(), |mut acc, (key, value)| {
                    acc.entry(key[depth]).or_default().push((key, value));
                    acc
                });

        let mut futures: FuturesUnordered<_> = grouped
            .into_iter()
            .map(|(index, group)| async move {
                self.child_with_ensure_loaded(&index, depth, transport)
                    .await?
                    .value()
                    .batch_insert_inner(group.into_iter(), transport, depth + 1)
                    .await
            })
            .collect();

        let mut changed = HashSet::new();

        while let Some(result) = futures.next().await {
            changed.extend(result?);
        }

        changed.insert(self.recalc_hash().await);

        Ok(changed)
    }

    pub async fn get(
        &self,
        key_hash: HashArray<H>,
        transport: &Transport,
    ) -> Result<Option<HashArray<H>>> {
        self.get_inner(H::convert_to_key(key_hash), transport, 0)
            .await
    }

    async fn get_inner(
        &self,
        key: KeyArray<H>,
        transport: &Transport,
        depth: usize,
    ) -> Result<Option<HashArray<H>>> {
        let entry = match self.children.get(&key[depth]) {
            Some(entry) => entry,
            None => return Ok(None),
        };

        if Self::is_last_stub(depth) {
            return Ok(Some(entry.value().hash().await));
        }

        let child = entry.value();
        child.ensure_loaded(depth, transport).await?;

        Box::pin(child.get_inner(key, transport, depth + 1)).await
    }

    pub async fn batch_get<I>(
        &self,
        iter: I,
        transport: &Transport,
    ) -> Result<HashMap<HashArray<H>, HashArray<H>>>
    where
        I: IntoIterator<Item = HashArray<H>>,
    {
        self.batch_get_inner(iter.into_iter().map(H::convert_to_key), transport, 0)
            .await
    }

    async fn batch_get_inner<I>(
        &self,
        iter: I,
        transport: &Transport,
        depth: usize,
    ) -> Result<HashMap<HashArray<H>, HashArray<H>>>
    where
        I: IntoIterator<Item = KeyArray<H>>,
    {
        if Self::is_last_stub(depth) {
            return Ok(stream::iter(iter)
                .filter_map(|key| async move {
                    if let Some(entry) = self.children.get(&key[depth]) {
                        let key = H::convert_to_hash(key);
                        let hash = entry.value().hash().await;
                        Some((key, hash))
                    } else {
                        None
                    }
                })
                .collect::<HashMap<_, _>>()
                .await);
        }

        let grouped: HashMap<_, Vec<_>> =
            iter.into_iter().fold(HashMap::new(), |mut grouped, key| {
                let index = key[depth];
                if self.child(&index).is_some() {
                    grouped.entry(index).or_default().push(key);
                }
                grouped
            });

        let mut futures: FuturesUnordered<_> = grouped
            .into_iter()
            .map(|(index, keys)| {
                // safe to unwrap because we checked if the child exists
                let entry = self.children.get(&index).unwrap();

                async move {
                    entry.value().ensure_loaded(depth, transport).await?;
                    entry
                        .value()
                        .batch_get_inner(keys, transport, depth + 1)
                        .await
                }
            })
            .collect();

        let mut collected = HashMap::new();

        while let Some(result) = futures.next().await {
            collected.extend(result?);
        }

        Ok(collected)
    }

    pub async fn hash(&self) -> HashArray<H> {
        self.hash.read().await.clone()
    }

    pub fn child(&self, index: &H::BanchingFactor) -> Option<Entry<H::BanchingFactor, Node<H>>> {
        self.children.get(index)
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        Self::try_from(slice)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.into()
    }
}

pub async fn calc_hash<H: HasherConfig>(
    children: &ChildrenMap<H>,
) -> GenericArray<u8, <H as Hasher>::OutputSizeInBytes> {
    if children.is_empty() {
        return GenericArray::default();
    }

    let hash_bytes = stream::iter(children.iter())
        .then(|entry| async move { entry.value().hash().await })
        .fold(Vec::new(), |mut acc, hash| async move {
            acc.extend(hash);
            acc
        })
        .await;

    <H as Hasher>::hash(&hash_bytes)
}

impl<H: HasherConfig> Default for Node<H> {
    fn default() -> Self {
        Node {
            hash: RwLock::new(HashArray::<H>::default()),
            children: SkipMap::new(),
        }
    }
}

impl<H: HasherConfig> From<Node<H>> for Vec<u8> {
    fn from(node: Node<H>) -> Self {
        (&node).into()
    }
}

impl<H: HasherConfig> From<&Node<H>> for Vec<u8> {
    fn from(node: &Node<H>) -> Self {
        bincode::serde::encode_to_vec(node, bincode::config::standard())
            .expect("Failed to serialize Node")
    }
}

impl<H: HasherConfig> TryFrom<Vec<u8>> for Node<H> {
    type Error = Error;

    fn try_from(vec: Vec<u8>) -> Result<Self> {
        Self::try_from(vec.as_slice())
    }
}

impl<H: HasherConfig> TryFrom<&[u8]> for Node<H> {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self> {
        bincode::serde::decode_from_slice(slice, bincode::config::standard())
            .map(|(n, _)| n)
            .map_err(Error::from)
    }
}

impl<H: HasherConfig> Serialize for Node<H> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = Vec::with_capacity(
            self.children.len() * (H::BANCHING_FACTOR_SIZE + H::OUTPUT_SIZE_IN_BIT / 8),
        );

        self.children.iter().for_each(|entry| {
            bytes.extend(H::serialize_banching_factor(entry.key()));
            bytes.extend_from_slice(&entry.value().hash.try_read().expect("Failed to read hash"));
        });

        serializer.serialize_bytes(&bytes)
    }
}

impl<'de, H: HasherConfig> Deserialize<'de> for Node<H> {
    fn deserialize<DE>(deserializer: DE) -> std::result::Result<Self, DE::Error>
    where
        DE: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;

        let children_len = H::BANCHING_FACTOR_SIZE + H::OUTPUT_SIZE_IN_BIT / 8;

        if bytes.is_empty() || bytes.len() % children_len != 0 {
            return Err(serde::de::Error::custom("Invalid byte length"));
        }

        let children_count = bytes.len() / children_len;

        let mut hashes = Vec::with_capacity(H::OUTPUT_SIZE_IN_BIT / 8 * children_count);

        let children =
            bytes
                .chunks_exact(children_len)
                .fold(ChildrenMap::default(), |children, chunk| {
                    let index = H::deserialize_banching_factor(&chunk[..H::BANCHING_FACTOR_SIZE])
                        .expect("Failed to deserialize index");
                    let hash = HashArray::<H>::from_slice(&chunk[H::BANCHING_FACTOR_SIZE..]);
                    hashes.extend_from_slice(hash);
                    children.insert(index, Node::with_hash(hash.clone()));
                    children
                });

        let hash = <H as Hasher>::hash(&hashes);

        Ok(Node {
            hash: RwLock::new(hash),
            children,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_1: HashArray<sha2::Sha256> = GenericArray::from_array([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ]);

    const KEY_2: HashArray<sha2::Sha256> = GenericArray::from_array([
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e,
        0x3f, 0x40,
    ]);

    const HASH_1: HashArray<sha2::Sha256> = GenericArray::from_array([
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e,
        0x5f, 0x60,
    ]);

    const HASH_2: HashArray<sha2::Sha256> = GenericArray::from_array([
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e,
        0x7f, 0x80,
    ]);

    #[tokio::test]
    async fn insert_and_get() {
        let node = Node::<sha2::Sha256>::default();
        let transport = Transport::default();

        let changed = node.insert(KEY_1, HASH_1, &transport).await.unwrap();

        let same = node.get(KEY_1, &transport).await.unwrap();
        let different = node.get(KEY_2, &transport).await.unwrap();

        assert_eq!(same, Some(HASH_1));
        assert_eq!(different, None);
        assert_eq!(changed.len(), sha2::Sha256::DEPTH);
        assert!(changed.contains(&node.hash().await));
    }

    #[tokio::test]
    async fn batch_insert_and_get() {
        let node = Node::<sha2::Sha256>::default();
        let transport = Transport::default();

        let pairs = vec![(KEY_1, HASH_1), (KEY_2, HASH_2)];
        let _ = node.batch_insert(pairs, &transport).await.unwrap();

        let results = node
            .batch_get(vec![KEY_1, KEY_2], &transport)
            .await
            .unwrap();

        assert_eq!(results.get(&KEY_1), Some(&HASH_1));
        assert_eq!(results.get(&KEY_2), Some(&HASH_2));
    }

    #[tokio::test]
    async fn serialize_and_deserialize() {
        let node = Node::<sha2::Sha256>::default();
        let transport = Transport::default();

        node.insert(KEY_1, HASH_1, &transport).await.unwrap();

        let serialized = node.to_bytes();
        let deserialized = Node::<sha2::Sha256>::from_slice(&serialized).unwrap();

        assert_eq!(node.children.len(), deserialized.children.len());
        assert_eq!(node.hash().await, deserialized.hash().await);
    }
}
