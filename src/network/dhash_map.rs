use std::{marker::PhantomData, sync::Arc};

use crate::{
    crypto::{traits::hasher::Multihash, Hasher},
    network::{dhash_map::node::Node, transport},
    traits::{serializable, Serializable},
};

#[cfg(not(test))]
use crate::network::transport::Transport;

#[cfg(test)]
use crate::network::transport::MockTransport as Transport;

const KEY_LENGTH: usize = 16;
type KeyArray = [u16; KEY_LENGTH];

type Result<T, E = Error> = std::result::Result<T, E>;

mod node;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Serializable(#[from] serializable::Error),

    #[error("{0}")]
    Transport(#[from] transport::Error),

    #[error("Node not found")]
    NodeNotFound,
}

pub struct DHashMap<K, V, H = sha2::Sha256> {
    transport: Arc<Transport>,
    root: Node<V, H>,
    _marker: PhantomData<K>,
}

impl<K, V, H> DHashMap<K, V, H>
where
    K: Serializable + Send + Sync + 'static,
    V: Clone + Serializable + Send + Sync + 'static,
    H: Hasher,
{
    pub async fn new(transport: Arc<Transport>, root_hash: &Multihash) -> Result<Self> {
        let root = transport
            .get(root_hash)
            .await?
            .expect("Failed to get root node");

        Ok(Self {
            transport,
            root,
            _marker: PhantomData,
        })
    }

    pub async fn insert(&self, key: K, value: V) -> Result<()> {
        let key_hash = H::hash(&key.to_vec().expect("Key serialization failed"));
        let key = Self::multihash_to_key(key_hash);
        self.root.insert(key, value, &self.transport).await
    }

    fn multihash_to_key(key_hash: Multihash) -> [u16; KEY_LENGTH] {
        let mut key = [0u16; KEY_LENGTH];

        for (i, chunk) in key_hash.digest().chunks_exact(2).enumerate() {
            key[i] = u16::from_be_bytes([chunk[0], chunk[1]]);
        }

        key
    }

    pub async fn insert_by_hash(&self, key_hash: Multihash, value: V) -> Result<()> {
        let key = Self::multihash_to_key(key_hash);
        self.root.insert(key, value, &self.transport).await
    }

    pub async fn insert_by_key(&self, key: KeyArray, value: V) -> Result<()> {
        self.root.insert(key, value, &self.transport).await
    }

    pub async fn get(&self, key: K) -> Result<Option<V>> {
        let key_hash = H::hash(&key.to_vec().expect("Key serialization failed"));
        let key = Self::multihash_to_key(key_hash);
        self.root.get(key, &self.transport).await
    }

    pub async fn get_by_hash(&self, key_hash: Multihash) -> Result<Option<V>> {
        let key = Self::multihash_to_key(key_hash);
        self.root.get(key, &self.transport).await
    }

    pub async fn get_by_key(&self, key: KeyArray) -> Result<Option<V>> {
        self.root.get(key, &self.transport).await
    }

    pub async fn extend<I>(&self, iter: I) -> Result<()>
    where
        I: IntoIterator<Item = (K, V)>,
    {
        self.root
            .batch_insert(
                iter.into_iter().map(|(k, v)| {
                    let key_hash = H::hash(&k.to_vec().expect("Key serialization failed"));
                    let key = Self::multihash_to_key(key_hash);
                    (key, v)
                }),
                &self.transport,
            )
            .await
    }

    pub async fn extend_by_hash<I>(&self, iter: I) -> Result<()>
    where
        I: IntoIterator<Item = (Multihash, V)>,
    {
        self.root
            .batch_insert(
                iter.into_iter()
                    .map(|(k, v)| (Self::multihash_to_key(k), v)),
                &self.transport,
            )
            .await
    }

    pub async fn extend_by_key<I>(&self, iter: I) -> Result<()>
    where
        I: IntoIterator<Item = (KeyArray, V)>,
    {
        self.root
            .batch_insert(iter.into_iter(), &self.transport)
            .await
    }

    pub async fn reset_root(&mut self, new_root: Node<V, H>) {
        self.root = new_root;
    }
}
