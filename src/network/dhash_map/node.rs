use std::{collections::HashMap, sync::Arc};

use crossbeam_skiplist::{map::Entry, SkipMap};
use dashmap::DashMap;
use futures::{
    stream::{self, FuturesUnordered},
    StreamExt, TryStreamExt,
};
use generic_array::{typenum::Unsigned, GenericArray};
use tokio::sync::RwLock;

use crate::{
    crypto::traits::hasher::HashArray,
    network::dhash_map::{Config, Error},
    traits::{serializable, ConstantSize, Serializable},
};

#[cfg(not(test))]
use crate::network::transport::Transport;

#[cfg(test)]
use crate::network::transport::MockTransport as Transport;

type KeyArray<H> = GenericArray<<H as Config>::Key, <H as Config>::KeyLength>;
type Result<T, E = Error> = std::result::Result<T, E>;

pub struct Node<V, H: Config> {
    hash: RwLock<HashArray<H>>,
    value: Option<V>,
    children: SkipMap<H::Key, Node<V, H>>,
}

impl<V, H: Config> Node<V, H>
where
    V: Clone + Serializable + Send + Sync + 'static,
{
    pub fn new_leaf(value: V) -> Result<Self> {
        let hash = H::hash(&value.to_vec()?);

        Ok(Node {
            hash: RwLock::new(hash),
            value: Some(value),
            children: SkipMap::new(),
        })
    }

    pub async fn insert(&self, key: KeyArray<H>, value: V, transport: &Transport) -> Result<()> {
        self.insert_inner(key, value, transport, 0).await
    }

    async fn insert_inner(
        &self,
        key: KeyArray<H>,
        value: V,
        transport: &Transport,
        depth: usize,
    ) -> Result<()> {
        if depth == H::KeyLength::USIZE - 1 {
            self.children.insert(key[depth], Node::new_leaf(value)?);
            self.update_hash(transport).await?;
            return Ok(());
        }

        let entry = self.ensure_loaded(key[depth], transport).await?;
        Box::pin(entry.value().insert_inner(key, value, transport, depth + 1)).await
    }

    async fn update_hash(&self, transport: &Transport) -> Result<()> {
        let hash = calc_hash(&self.children).await;
        transport.put_with_key::<H>(&hash, self.to_vec()?).await?;
        *self.hash.write().await = hash;
        Ok(())
    }

    async fn ensure_loaded(
        &self,
        key: H::Key,
        transport: &Transport,
    ) -> Result<Entry<H::Key, Node<V, H>>> {
        match self.children.get(&key) {
            Some(entry) => {
                let node = entry.value();

                if !node.children.is_empty() || node.value.is_some() {
                    return Ok(entry);
                }

                let fetched = transport
                    .get::<H, Node<V, H>>(&node.hash().await)
                    .await?
                    .ok_or(Error::NodeNotFound)?;

                fetched.children.into_iter().for_each(|(k, v)| {
                    node.children.insert(k, v);
                });

                Ok(entry)
            }
            None => {
                self.children.insert(key, Node::default());
                Ok(self.children.get(&key).unwrap())
            }
        }
    }

    pub async fn hash(&self) -> HashArray<H> {
        self.hash.read().await.clone()
    }

    pub async fn batch_insert<I>(&self, iter: I, transport: &Transport) -> Result<()>
    where
        I: IntoIterator<Item = (KeyArray<H>, V)>,
    {
        self.batch_insert_inner(iter, transport, 0).await
    }

    async fn batch_insert_inner<I>(
        &self,
        iter: I,
        transport: &Transport,
        depth: usize,
    ) -> Result<()>
    where
        I: IntoIterator<Item = (KeyArray<H>, V)>,
    {
        if depth == H::KeyLength::USIZE - 1 {
            for (key, value) in iter {
                self.children.insert(key[depth], Node::new_leaf(value)?);
            }
            self.update_hash(transport).await?;
            return Ok(());
        }

        let grouped: HashMap<_, Vec<_>> =
            iter.into_iter()
                .fold(HashMap::new(), |mut acc, (key, value)| {
                    acc.entry(key[depth]).or_default().push((key, value));
                    acc
                });

        grouped
            .into_iter()
            .map(|(key, values)| async move {
                self.ensure_loaded(key, transport)
                    .await?
                    .value()
                    .batch_insert_inner(values.into_iter(), transport, depth + 1)
                    .await
            })
            .collect::<FuturesUnordered<_>>()
            .try_collect::<Vec<_>>()
            .await?;

        self.update_hash(transport).await?;

        Ok(())
    }

    pub async fn get(&self, key: KeyArray<H>, transport: &Transport) -> Result<Option<V>> {
        self.get_inner(key, transport, 0).await
    }

    async fn get_inner(
        &self,
        key: KeyArray<H>,
        transport: &Transport,
        depth: usize,
    ) -> Result<Option<V>> {
        let entry = self.ensure_loaded(key[depth], transport).await?;

        if depth == H::KeyLength::USIZE - 1 {
            return Ok(entry.value().value.clone());
        }

        Box::pin(entry.value().get_inner(key, transport, depth + 1)).await
    }

    pub async fn batch_get<I>(
        &self,
        iter: I,
        transport: &Transport,
    ) -> Result<impl IntoIterator<Item = (KeyArray<H>, Option<V>)>>
    where
        I: IntoIterator<Item = KeyArray<H>>,
    {
        let results = Arc::new(DashMap::new());
        self.batch_get_inner(iter, transport, 0, Arc::clone(&results))
            .await?;

        let results = match Arc::try_unwrap(results) {
            Ok(map) => map,
            Err(_) => panic!("Failed to unwrap Arc<DashMap>"),
        };

        Ok(results.into_iter().map(|(key, value)| (key, value)))
    }

    async fn batch_get_inner<I>(
        &self,
        iter: I,
        transport: &Transport,
        depth: usize,
        results: Arc<DashMap<KeyArray<H>, Option<V>>>,
    ) -> Result<()>
    where
        I: IntoIterator<Item = KeyArray<H>>,
    {
        if depth == H::KeyLength::USIZE - 1 {
            for key in iter {
                let node_key = key[depth];
                if let Some(entry) = self.children.get(&node_key) {
                    results.insert(key, entry.value().value.clone());
                } else {
                    results.insert(key, None);
                }
            }
            return Ok(());
        }

        let grouped: HashMap<H::Key, Vec<KeyArray<H>>> =
            iter.into_iter().fold(HashMap::new(), |mut acc, key| {
                acc.entry(key[depth]).or_default().push(key);
                acc
            });

        grouped
            .into_iter()
            .map(|(node_key, keys)| {
                let results = Arc::clone(&results);
                async move {
                    match self.ensure_loaded(node_key, transport).await {
                        Ok(entry) => {
                            entry
                                .value()
                                .batch_get_inner(keys, transport, depth + 1, results)
                                .await
                        }
                        Err(_) => {
                            keys.into_iter().for_each(|key| {
                                results.insert(key, None);
                            });
                            Ok(())
                        }
                    }
                }
            })
            .collect::<FuturesUnordered<_>>()
            .try_collect::<Vec<_>>()
            .await?;

        Ok(())
    }
}

async fn calc_hash<V, H>(children: &SkipMap<H::Key, Node<V, H>>) -> HashArray<H>
where
    V: Clone + Serializable + Send + Sync + 'static,
    H: Config,
{
    if children.is_empty() {
        return HashArray::<H>::default();
    }

    let capacity = children.len() * H::KeyLength::USIZE;

    let bytes = stream::iter(children.iter())
        .then(|entry| async move { entry.value().hash().await })
        .fold(Vec::with_capacity(capacity), |mut acc, hash| async move {
            acc.extend(hash);
            acc
        })
        .await;

    H::hash(&bytes)
}

impl<V, H> Default for Node<V, H>
where
    V: Clone + Serializable + Send + Sync + 'static,
    H: Config,
{
    fn default() -> Self {
        Node {
            hash: RwLock::new(HashArray::<H>::default()),
            value: None,
            children: SkipMap::new(),
        }
    }
}

impl<V, H> Serializable for Node<V, H>
where
    V: Clone + Serializable + Send + Sync + 'static,
    H: Config,
{
    fn serialized_size(&self) -> usize {
        self.value.serialized_size()
            + usize::SIZE
            + (HashArray::<H>::SIZE + H::Key::SIZE) * self.children.len()
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        self.value.to_writer(writer)?;
        self.children.len().to_writer(writer)?;
        self.children.iter().try_for_each(|entry| {
            entry.key().to_writer(writer)?;
            entry
                .value()
                .hash
                .try_read()
                .map_err(|e| serializable::Error(e.to_string()))?
                .to_writer(writer)?;

            Ok(())
        })
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        let value = Option::<V>::from_reader(reader)?;
        let children_len = usize::from_reader(reader)?;

        let children = SkipMap::new();
        let mut hash_bytes = Vec::with_capacity(children_len * HashArray::<H>::SIZE);
        for _ in 0..children_len {
            let key = H::Key::from_reader(reader)?;
            let hash = HashArray::<H>::from_reader(reader)?;
            let node = Node {
                hash: RwLock::new(hash.clone()),
                value: None,
                children: SkipMap::new(),
            };
            children.insert(key, node);
            hash_bytes.extend(hash);
        }

        let hash = H::hash(&hash_bytes);

        Ok(Node {
            hash: RwLock::new(hash),
            value,
            children,
        })
    }
}
