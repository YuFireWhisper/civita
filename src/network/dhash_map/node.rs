use std::{collections::HashMap, marker::PhantomData, sync::Arc};

use crossbeam_skiplist::{map::Entry, SkipMap};
use dashmap::DashMap;
use futures::{
    stream::{self, FuturesUnordered},
    StreamExt, TryStreamExt,
};
use libp2p::multihash;
use tokio::sync::RwLock;

use crate::{
    crypto::{traits::hasher::Multihash, Hasher},
    network::dhash_map::{Error, KeyArray, KEY_LENGTH},
    traits::{serializable, Serializable},
};

#[cfg(not(test))]
use crate::network::transport::Transport;

#[cfg(test)]
use crate::network::transport::MockTransport as Transport;

type Result<T, E = Error> = std::result::Result<T, E>;

pub struct Node<V, H> {
    hash: RwLock<Multihash>,
    value: Option<V>,
    children: SkipMap<u16, Node<V, H>>,
    _marker: PhantomData<H>,
}

impl<V, H> Node<V, H>
where
    V: Clone + Serializable + Send + Sync + 'static,
    H: Hasher,
{
    pub fn with_value(value: V) -> Result<Self> {
        let hash = H::hash(&value.to_vec()?);

        Ok(Node {
            hash: RwLock::new(hash),
            value: Some(value),
            children: SkipMap::new(),
            _marker: PhantomData,
        })
    }

    pub fn with_hash(hash: Multihash) -> Self {
        Node {
            hash: RwLock::new(hash),
            value: None,
            children: SkipMap::new(),
            _marker: PhantomData,
        }
    }

    pub async fn insert(&self, key: KeyArray, value: V, transport: &Transport) -> Result<()> {
        self.insert_inner(key, value, transport, 0).await
    }

    async fn insert_inner(
        &self,
        key: KeyArray,
        value: V,
        transport: &Transport,
        depth: usize,
    ) -> Result<()> {
        if depth == KEY_LENGTH - 1 {
            self.children.insert(key[depth], Node::with_value(value)?);
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
        key: u16,
        transport: &Transport,
    ) -> Result<Entry<u16, Node<V, H>>> {
        match self.children.get(&key) {
            Some(entry) => {
                let node = entry.value();

                if !node.children.is_empty() || node.value.is_some() {
                    return Ok(entry);
                }

                let fetched = transport
                    .get::<Node<V, H>>(&*node.hash.read().await)
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

    pub async fn hash(&self) -> Multihash {
        self.hash.read().await.clone()
    }

    pub async fn batch_insert<I>(&self, iter: I, transport: &Transport) -> Result<()>
    where
        I: IntoIterator<Item = (KeyArray, V)>,
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
        I: IntoIterator<Item = (KeyArray, V)>,
    {
        if depth == KEY_LENGTH - 1 {
            for (key, value) in iter {
                self.children.insert(key[depth], Node::with_value(value)?);
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

    pub async fn get(&self, key: KeyArray, transport: &Transport) -> Result<Option<V>> {
        self.get_inner(key, transport, 0).await
    }

    async fn get_inner(
        &self,
        key: KeyArray,
        transport: &Transport,
        depth: usize,
    ) -> Result<Option<V>> {
        let entry = self.ensure_loaded(key[depth], transport).await?;

        if depth == KEY_LENGTH - 1 {
            return Ok(entry.value().value.clone());
        }

        Box::pin(entry.value().get_inner(key, transport, depth + 1)).await
    }

    pub async fn batch_get<I>(
        &self,
        iter: I,
        transport: &Transport,
    ) -> Result<impl IntoIterator<Item = (KeyArray, Option<V>)>>
    where
        I: IntoIterator<Item = KeyArray>,
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
        results: Arc<DashMap<KeyArray, Option<V>>>,
    ) -> Result<()>
    where
        I: IntoIterator<Item = KeyArray>,
    {
        if depth == KEY_LENGTH - 1 {
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

        let grouped: HashMap<_, Vec<_>> = iter.into_iter().fold(HashMap::new(), |mut acc, key| {
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

async fn calc_hash<V, H>(children: &SkipMap<u16, Node<V, H>>) -> Multihash
where
    V: Clone + Serializable + Send + Sync + 'static,
    H: Hasher,
{
    if children.is_empty() {
        return Multihash::default();
    }

    let bytes = stream::iter(children.iter())
        .then(|entry| async move { entry.value().hash().await })
        .fold(Vec::<u8>::new(), |mut acc, hash| async move {
            acc.extend(hash.to_bytes());
            acc
        })
        .await;

    H::hash(&bytes)
}

impl<V, H> Default for Node<V, H> {
    fn default() -> Self {
        Node {
            hash: RwLock::new(Multihash::default()),
            value: None,
            children: SkipMap::new(),
            _marker: PhantomData,
        }
    }
}

impl<V, H> Serializable for Node<V, H>
where
    V: Clone + Serializable + Send + Sync + 'static,
    H: Hasher,
{
    fn serialized_size(&self) -> usize {
        unimplemented!()
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        self.value.to_writer(writer)?;

        self.children.len().to_writer(writer)?;
        self.children.iter().try_for_each(|entry| {
            entry.key().to_writer(writer)?;

            let child = entry.value().hash.try_read().expect("Failed to read hash");
            child.code().to_writer(writer)?;
            child.size().to_writer(writer)?;
            writer.write_all(child.digest())?;

            Ok(())
        })
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        let value = Option::<V>::from_reader(reader)?;

        let children_len = usize::from_reader(reader)?;
        let children = SkipMap::new();

        let mut hash_bytes = Vec::new();
        for _ in 0..children_len {
            let key = u16::from_reader(reader)?;

            let code = u64::from_reader(reader)?;
            hash_bytes.extend_from_slice(&code.to_be_bytes());

            let size = u8::from_reader(reader)?;
            hash_bytes.push(size);

            let mut digest = vec![0u8; size as usize];
            reader.read_exact(&mut digest)?;
            hash_bytes.extend_from_slice(&digest);

            let hash = Multihash::wrap(code, &digest)?;
            let node = Node::<V, H>::with_hash(hash);

            children.insert(key, node);
        }

        let hash = H::hash(&hash_bytes);

        Ok(Node {
            hash: RwLock::new(hash),
            value,
            children,
            _marker: PhantomData,
        })
    }
}

impl From<multihash::Error> for serializable::Error {
    fn from(err: multihash::Error) -> Self {
        serializable::Error(err.to_string())
    }
}
