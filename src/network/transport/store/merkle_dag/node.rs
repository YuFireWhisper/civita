use std::collections::{HashMap, HashSet};

use crossbeam::atomic::AtomicCell;
use crossbeam_skiplist::{map::Entry, SkipMap};
use futures::{stream::FuturesUnordered, StreamExt};
use serde::{Deserialize, Serialize};

use crate::{
    constants::{HASH_ARRAY_LENGTH, USIZE_LENGTH},
    network::transport::store::merkle_dag::{
        BanchingFactor, Error, HashArray, KeyArray, Result, DEPTH,
    },
};

#[cfg(not(test))]
use crate::network::transport::Transport;

#[cfg(test)]
use crate::network::transport::MockTransport as Transport;

#[derive(Debug)]
#[derive(Default)]
pub struct Node {
    hash: AtomicCell<HashArray>,
    children: SkipMap<BanchingFactor, Node>,
    depth: usize,
}

impl Node {
    pub fn with_hash(hash: HashArray, depth: usize) -> Self {
        Node {
            hash: AtomicCell::new(hash),
            depth,
            ..Default::default()
        }
    }

    pub fn with_children(children: SkipMap<BanchingFactor, Node>, depth: usize) -> Self {
        Node {
            hash: AtomicCell::new(calc_hash(&children)),
            children,
            depth,
        }
    }

    pub fn with_depth(depth: usize) -> Self {
        Node {
            depth,
            ..Default::default()
        }
    }

    pub async fn insert(
        &self,
        key: KeyArray,
        value: HashArray,
        transport: &Transport,
    ) -> Result<HashSet<HashArray>> {
        let mut changed = HashSet::new();
        self.insert_inner(key, value, transport, &mut changed)
            .await?;
        Ok(changed)
    }

    async fn insert_inner(
        &self,
        key: KeyArray,
        value: HashArray,
        transport: &Transport,
        changed: &mut HashSet<HashArray>,
    ) -> Result<()> {
        if self.is_last_stub() {
            self.insert_child(key[self.depth], value);
            changed.insert(self.recalc_hash());
            return Ok(());
        }

        let entry = self.get_or_insert(key[self.depth]);

        entry.value().ensure_loaded(transport).await?;
        Box::pin(entry.value().insert_inner(key, value, transport, changed)).await?;

        changed.insert(self.recalc_hash());

        Ok(())
    }

    fn is_last_stub(&self) -> bool {
        self.depth == DEPTH - 1
    }

    fn insert_child(&self, index: BanchingFactor, hash: HashArray) {
        self.children
            .insert(index, Node::with_hash(hash, self.depth + 1));
    }

    fn get_or_insert(&self, index: BanchingFactor) -> Entry<BanchingFactor, Node> {
        self.children
            .get_or_insert(index, Node::with_depth(self.depth + 1))
    }

    async fn ensure_loaded(&self, transport: &Transport) -> Result<()> {
        if !self.is_leaf() && self.children.is_empty() && self.hash.load() != HashArray::default() {
            let fetched = transport.get_or_error::<Node>(&self.hash()).await?;

            self.children.clear();
            fetched.children.into_iter().for_each(|(index, child)| {
                self.children.insert(index, child);
            });
        }

        Ok(())
    }

    fn is_leaf(&self) -> bool {
        self.depth == DEPTH
    }

    fn recalc_hash(&self) -> HashArray {
        if self.children.is_empty() {
            return self.hash.load();
        }

        let new_hash = calc_hash(&self.children);
        self.hash.store(new_hash);
        new_hash
    }

    pub async fn batch_insert<I>(
        &self,
        iter: I,
        transport: &Transport,
    ) -> Result<HashSet<HashArray>>
    where
        I: IntoIterator<Item = (KeyArray, HashArray)>,
    {
        if self.is_last_stub() {
            iter.into_iter().for_each(|(key, value)| {
                self.insert_child(key[self.depth], value);
            });

            return Ok(HashSet::from([self.recalc_hash()]));
        }

        let grouped: HashMap<_, Vec<_>> =
            iter.into_iter()
                .fold(HashMap::new(), |mut acc, (key, value)| {
                    acc.entry(key[self.depth]).or_default().push((key, value));
                    acc
                });

        let mut futures: FuturesUnordered<_> = grouped
            .into_iter()
            .map(|(index, group)| {
                let entry = self.get_or_insert(index);

                async move {
                    entry.value().ensure_loaded(transport).await?;
                    entry
                        .value()
                        .batch_insert(group.into_iter(), transport)
                        .await
                }
            })
            .collect();

        let mut changed = HashSet::new();

        while let Some(result) = futures.next().await {
            changed.extend(result?);
        }

        changed.insert(self.recalc_hash());

        Ok(changed)
    }

    pub async fn get(&self, key: KeyArray, transport: &Transport) -> Result<Option<HashArray>> {
        let entry = match self.children.get(&key[self.depth]) {
            Some(entry) => entry,
            None => return Ok(None),
        };

        let child = entry.value();

        if child.is_leaf() {
            return Ok(Some(child.hash()));
        }

        child.ensure_loaded(transport).await?;

        Box::pin(child.get(key, transport)).await
    }

    pub async fn batch_get<I>(
        &self,
        iter: I,
        transport: &Transport,
    ) -> Result<HashMap<KeyArray, HashArray>>
    where
        I: IntoIterator<Item = KeyArray>,
    {
        if self.is_last_stub() {
            return Ok(iter.into_iter().fold(HashMap::new(), |mut acc, key| {
                if let Some(entry) = self.children.get(&key[self.depth]) {
                    acc.insert(key, entry.value().hash());
                }
                acc
            }));
        }

        let grouped: HashMap<_, Vec<_>> =
            iter.into_iter().fold(HashMap::new(), |mut grouped, key| {
                let index = key[self.depth];
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
                    entry.value().ensure_loaded(transport).await?;
                    entry.value().batch_get(keys, transport).await
                }
            })
            .collect();

        let mut collected = HashMap::new();

        while let Some(result) = futures.next().await {
            collected.extend(result?);
        }

        Ok(collected)
    }

    pub fn hash(&self) -> HashArray {
        self.hash.load()
    }

    pub fn child(&self, index: &BanchingFactor) -> Option<Entry<BanchingFactor, Node>> {
        self.children.get(index)
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        Self::try_from(slice)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.into()
    }
}

fn calc_hash(children: &SkipMap<BanchingFactor, Node>) -> HashArray {
    if children.is_empty() {
        return HashArray::default();
    }

    let mut hasher = blake3::Hasher::new();
    children.iter().for_each(|entry| {
        hasher.update(&entry.value().hash());
    });

    hasher.finalize().into()
}

impl From<Node> for Vec<u8> {
    fn from(node: Node) -> Self {
        bincode::serde::encode_to_vec(&node, bincode::config::standard())
            .expect("Failed to serialize Node")
    }
}

impl From<&Node> for Vec<u8> {
    fn from(node: &Node) -> Self {
        bincode::serde::encode_to_vec(node, bincode::config::standard())
            .expect("Failed to serialize Node")
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
        bincode::serde::decode_from_slice(slice, bincode::config::standard())
            .map(|(n, _)| n)
            .map_err(Error::from)
    }
}

impl Serialize for Node {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = Vec::new();

        bytes.extend(self.depth.to_be_bytes());

        self.children.iter().for_each(|entry| {
            bytes.extend(entry.key().to_be_bytes());
            bytes.extend(entry.value().hash());
        });

        if self.is_leaf() {
            bytes.extend(self.hash());
        }

        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for Node {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const INDEX_LENGTH: usize = std::mem::size_of::<BanchingFactor>();
        const CHILDREN_SIZE: usize = INDEX_LENGTH + HASH_ARRAY_LENGTH;

        let bytes = Vec::<u8>::deserialize(deserializer)?;

        if bytes.len() < USIZE_LENGTH {
            return Err(serde::de::Error::custom("Byte length too short"));
        }

        let len = bytes.len() - USIZE_LENGTH;
        match len {
            HASH_ARRAY_LENGTH => {}
            _ if len % CHILDREN_SIZE == 0 => {}
            _ => {
                return Err(serde::de::Error::custom("Invalid byte length"));
            }
        }

        match usize::from_be_bytes(std::array::from_fn(|i| bytes[i])) {
            DEPTH => {
                let hash = std::array::from_fn(|i| bytes[USIZE_LENGTH + i]);
                Ok(Node::with_hash(hash, DEPTH))
            }

            depth if depth < DEPTH => {
                let children_depth = depth + 1;
                let children = SkipMap::new();

                bytes[USIZE_LENGTH..]
                    .chunks_exact(CHILDREN_SIZE)
                    .for_each(|chunk| {
                        let index =
                            BanchingFactor::from_be_bytes(std::array::from_fn(|i| chunk[i]));
                        let hash = std::array::from_fn(|i| chunk[INDEX_LENGTH + i]);
                        children.insert(index, Node::with_hash(hash, children_depth));
                    });

                Ok(Node::with_children(children, depth))
            }
            _ => Err(serde::de::Error::custom("Invalid depth")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_1: KeyArray = [1; DEPTH];
    const KEY_2: KeyArray = [2; DEPTH];

    const HASH_1: HashArray = [1; HASH_ARRAY_LENGTH];
    const HASH_2: HashArray = [2; HASH_ARRAY_LENGTH];

    #[tokio::test]
    async fn insert_and_get() {
        let node = Node::default();
        let transport = Transport::default();

        let changed = node.insert(KEY_1, HASH_1, &transport).await.unwrap();

        let same = node.get(KEY_1, &transport).await.unwrap();
        let different = node.get(KEY_2, &transport).await.unwrap();

        assert_eq!(same, Some(HASH_1));
        assert_eq!(different, None);
        assert_eq!(changed.len(), DEPTH);
        assert_ne!(node.hash(), HashArray::default());
        assert!(changed.contains(&node.hash()));
    }

    #[tokio::test]
    async fn batch_insert_and_get() {
        let node = Node::default();
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
        let node = Node::default();
        let transport = Transport::default();

        node.insert(KEY_1, HASH_1, &transport).await.unwrap();

        let serialized = node.to_bytes();
        let deserialized = Node::from_slice(&serialized).unwrap();

        assert_eq!(node.depth, deserialized.depth);
        assert_eq!(node.children.len(), deserialized.children.len());
        assert_eq!(node.hash(), deserialized.hash());
    }
}
