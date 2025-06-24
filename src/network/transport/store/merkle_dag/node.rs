use std::{
    collections::{HashMap, HashSet},
    marker::PhantomData,
};

use crossbeam_skiplist::{map::Entry, SkipMap};
use futures::{
    stream::{self, FuturesUnordered},
    StreamExt,
};
use generic_array::{typenum::Unsigned, GenericArray};
use tokio::sync::RwLock;

use crate::{
    crypto::traits::hasher::HashArray,
    network::transport::{
        store::merkle_dag::{Config, Error, KeyArray, Result},
        KadEngine,
    },
    traits::{serializable, ConstantSize, Serializable},
};

type ChildrenMap<C, K> = SkipMap<<C as Config>::BanchingFactor, Node<C, K>>;

pub struct Node<C: Config, K> {
    hash: RwLock<HashArray<C>>,
    children: ChildrenMap<C, K>,
    _marker: std::marker::PhantomData<K>,
}

impl<C: Config, K: KadEngine<C>> Node<C, K> {
    pub fn with_hash(hash: HashArray<C>) -> Self {
        Node {
            hash: RwLock::new(hash),
            ..Default::default()
        }
    }

    pub async fn with_children(children: ChildrenMap<C, K>) -> Self {
        Node {
            hash: RwLock::new(calc_hash(&children).await),
            children,
            ..Default::default()
        }
    }

    pub async fn insert(
        &self,
        key_hash: HashArray<C>,
        value: HashArray<C>,
        kad: &K,
    ) -> Result<HashSet<HashArray<C>>> {
        let key = C::convert_to_key(key_hash);
        self.insert_inner(key, value, kad, 0).await
    }

    async fn insert_inner(
        &self,
        key: KeyArray<C>,
        value: HashArray<C>,
        kad: &K,
        depth: usize,
    ) -> Result<HashSet<HashArray<C>>> {
        if Self::is_last_stub(depth) {
            self.children.insert(key[depth], Node::with_hash(value));
            return Ok(HashSet::from([self.recalc_hash().await]));
        }

        let entry = self
            .child_with_ensure_loaded(&key[depth], depth, kad)
            .await?;

        let mut changed = Box::pin(entry.value().insert_inner(key, value, kad, depth + 1)).await?;

        changed.insert(self.recalc_hash().await);

        Ok(changed)
    }

    fn is_last_stub(depth: usize) -> bool {
        depth == C::Depth::USIZE - 1
    }

    async fn child_with_ensure_loaded(
        &self,
        index: &C::BanchingFactor,
        depth: usize,
        kad: &K,
    ) -> Result<Entry<C::BanchingFactor, Node<C, K>>> {
        match self.children.get(index) {
            Some(entry) => {
                entry.value().ensure_loaded(depth, kad).await?;
                Ok(entry)
            }
            None => {
                self.children.insert(*index, Node::default());
                Ok(self.children.get(index).unwrap())
            }
        }
    }

    async fn ensure_loaded(&self, depth: usize, kad: &K) -> Result<()> {
        if self.is_missing(depth).await {
            let fetched = kad
                .get::<Node<C, K>>(&self.hash().await)
                .await?
                .ok_or_else(|| Error::NodeNotFound)?;

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
            && *self.hash.read().await == HashArray::<C>::default()
    }

    fn is_leaf(&self, depth: usize) -> bool {
        depth == C::Depth::USIZE
    }

    async fn recalc_hash(&self) -> HashArray<C> {
        if self.children.is_empty() {
            return HashArray::<C>::default();
        }

        let new_hash = calc_hash(&self.children).await;
        *self.hash.write().await = new_hash.clone();
        new_hash
    }

    pub async fn batch_insert<I>(&self, iter: I, kad: &K) -> Result<HashSet<HashArray<C>>>
    where
        I: IntoIterator<Item = (HashArray<C>, HashArray<C>)>,
    {
        let iter = iter.into_iter().map(|(k, v)| (C::convert_to_key(k), v));
        self.batch_insert_inner(iter, kad, 0).await
    }

    async fn batch_insert_inner<I>(
        &self,
        iter: I,
        kad: &K,
        depth: usize,
    ) -> Result<HashSet<HashArray<C>>>
    where
        I: IntoIterator<Item = (KeyArray<C>, HashArray<C>)>,
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
                self.child_with_ensure_loaded(&index, depth, kad)
                    .await?
                    .value()
                    .batch_insert_inner(group.into_iter(), kad, depth + 1)
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

    pub async fn get(&self, key_hash: HashArray<C>, kad: &K) -> Result<Option<HashArray<C>>> {
        self.get_inner(C::convert_to_key(key_hash), kad, 0).await
    }

    async fn get_inner(
        &self,
        key: KeyArray<C>,
        kad: &K,
        depth: usize,
    ) -> Result<Option<HashArray<C>>> {
        let entry = match self.children.get(&key[depth]) {
            Some(entry) => entry,
            None => return Ok(None),
        };

        if Self::is_last_stub(depth) {
            return Ok(Some(entry.value().hash().await));
        }

        let child = entry.value();
        child.ensure_loaded(depth, kad).await?;

        Box::pin(child.get_inner(key, kad, depth + 1)).await
    }

    pub async fn batch_get<I>(
        &self,
        iter: I,
        kad: &K,
    ) -> Result<HashMap<HashArray<C>, HashArray<C>>>
    where
        I: IntoIterator<Item = HashArray<C>>,
    {
        let iter = iter.into_iter().map(C::convert_to_key);
        self.batch_get_inner(iter, kad, 0).await
    }

    async fn batch_get_inner<I>(
        &self,
        iter: I,
        kad: &K,
        depth: usize,
    ) -> Result<HashMap<HashArray<C>, HashArray<C>>>
    where
        I: IntoIterator<Item = KeyArray<C>>,
    {
        if Self::is_last_stub(depth) {
            return Ok(stream::iter(iter)
                .filter_map(|key| async move {
                    if let Some(entry) = self.children.get(&key[depth]) {
                        let key = C::convert_to_hash(key);
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
                    entry.value().ensure_loaded(depth, kad).await?;
                    entry.value().batch_get_inner(keys, kad, depth + 1).await
                }
            })
            .collect();

        let mut collected = HashMap::new();

        while let Some(result) = futures.next().await {
            collected.extend(result?);
        }

        Ok(collected)
    }

    pub async fn hash(&self) -> HashArray<C> {
        self.hash.read().await.clone()
    }

    pub fn child(&self, index: &C::BanchingFactor) -> Option<Entry<C::BanchingFactor, Node<C, K>>> {
        self.children.get(index)
    }
}

pub async fn calc_hash<C: Config, K: KadEngine<C>>(children: &ChildrenMap<C, K>) -> HashArray<C> {
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

    C::hash(&hash_bytes)
}

impl<C: Config, K> Default for Node<C, K> {
    fn default() -> Self {
        Node {
            hash: RwLock::new(HashArray::<C>::default()),
            children: SkipMap::new(),
            _marker: std::marker::PhantomData,
        }
    }
}

impl<C: Config, K: KadEngine<C>> Serializable for Node<C, K> {
    fn serialized_size(&self) -> usize {
        self.children.len() * (C::BanchingFactor::SIZE + C::OutputSizeInBytes::USIZE)
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        let len = usize::from_reader(reader)?;

        let children = ChildrenMap::<C, K>::default();
        let mut hashes = Vec::with_capacity(C::OutputSizeInBytes::USIZE * len);

        for _ in 0..len {
            let key = C::BanchingFactor::from_reader(reader)?;
            let hash = HashArray::<C>::from_reader(reader)?;
            hashes.extend_from_slice(&hash);
            children.insert(key, Node::with_hash(hash));
        }

        let hash = C::hash(&hashes);

        Ok(Node {
            hash: RwLock::new(hash),
            children,
            _marker: PhantomData,
        })
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        writer.write_all(&self.children.len().to_be_bytes())?;

        self.children.iter().try_for_each(|entry| {
            entry.key().to_writer(writer)?;
            entry
                .value()
                .hash
                .try_read()
                .expect("Failed to read hash")
                .to_writer(writer)?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::network::transport::MockKadEngine;

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

    type Hasher = sha2::Sha256;

    #[tokio::test]
    async fn insert_and_get() {
        let node = Node::<Hasher, MockKadEngine<Hasher>>::default();
        let kad = MockKadEngine::<Hasher>::default();

        let changed = node.insert(KEY_1, HASH_1, &kad).await.unwrap();

        let same = node.get(KEY_1, &kad).await.unwrap();
        let different = node.get(KEY_2, &kad).await.unwrap();

        assert_eq!(same, Some(HASH_1));
        assert_eq!(different, None);
        assert_eq!(changed.len(), <Hasher as Config>::Depth::USIZE);
        assert!(changed.contains(&node.hash().await));
    }

    #[tokio::test]
    async fn batch_insert_and_get() {
        let node = Node::<sha2::Sha256, MockKadEngine<Hasher>>::default();
        let kad = MockKadEngine::<Hasher>::default();

        let pairs = vec![(KEY_1, HASH_1), (KEY_2, HASH_2)];
        let _ = node.batch_insert(pairs, &kad).await.unwrap();

        let results = node.batch_get(vec![KEY_1, KEY_2], &kad).await.unwrap();

        assert_eq!(results.get(&KEY_1), Some(&HASH_1));
        assert_eq!(results.get(&KEY_2), Some(&HASH_2));
    }

    #[tokio::test]
    async fn serialize_and_deserialize() {
        let node = Node::<sha2::Sha256, MockKadEngine<Hasher>>::default();
        let kad = MockKadEngine::<Hasher>::default();

        node.insert(KEY_1, HASH_1, &kad).await.unwrap();

        let serialized = node.to_vec().expect("Serialization failed");
        let deserialized =
            Node::<sha2::Sha256, MockKadEngine<Hasher>>::from_slice(&serialized).unwrap();

        assert_eq!(node.children.len(), deserialized.children.len());
        assert_eq!(node.hash().await, deserialized.hash().await);
    }
}
