use std::{hash::Hash, marker::PhantomData, sync::Arc};

use generic_array::{ArrayLength, GenericArray};

use crate::{
    crypto::{traits::hasher::HashArray, Hasher},
    network::{dhash_map::node::Node, transport},
    traits::{serializable, ConstantSize, Serializable},
};

#[cfg(not(test))]
use crate::network::transport::Transport;

#[cfg(test)]
use crate::network::transport::MockTransport as Transport;

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

pub trait Config: Hasher {
    type Key: Copy + Clone + Eq + Ord + Hash + Serializable + ConstantSize + Send + Sync;
    type KeyLength: ArrayLength;

    fn convert_to_key(hash: HashArray<Self>) -> GenericArray<Self::Key, Self::KeyLength>;
}

pub struct DHashMap<K, V, H>
where
    K: Serializable,
    V: Clone + Serializable + Send + Sync + 'static,
    H: Config,
{
    transport: Arc<Transport>,
    root: Node<V, H>,
    _marker: PhantomData<(K, H)>,
}

impl<K, V, H> DHashMap<K, V, H>
where
    K: Serializable + Send + Sync + 'static,
    V: Clone + Serializable + Send + Sync + 'static,
    H: Config,
{
    pub fn new(transport: Arc<Transport>, root: Node<V, H>) -> Self {
        Self {
            transport,
            root,
            _marker: PhantomData,
        }
    }

    pub async fn insert(&self, key: K, value: V) -> Result<()> {
        let key_hash = H::hash(&key.to_vec().expect("Key serialization failed"));
        let key = H::convert_to_key(key_hash);
        self.root.insert(key, value, &self.transport).await
    }

    pub async fn insert_by_hash(&self, key_hash: HashArray<H>, value: V) -> Result<()> {
        let key = H::convert_to_key(key_hash);
        self.root.insert(key, value, &self.transport).await
    }

    pub async fn insert_by_key(
        &self,
        key: GenericArray<H::Key, H::KeyLength>,
        value: V,
    ) -> Result<()> {
        self.root.insert(key, value, &self.transport).await
    }

    pub async fn get(&self, key: K) -> Result<Option<V>> {
        let key_hash = H::hash(&key.to_vec().expect("Key serialization failed"));
        let key = H::convert_to_key(key_hash);
        self.root.get(key, &self.transport).await
    }

    pub async fn get_by_hash(&self, key_hash: HashArray<H>) -> Result<Option<V>> {
        let key = H::convert_to_key(key_hash);
        self.root.get(key, &self.transport).await
    }

    pub async fn get_by_key(&self, key: GenericArray<H::Key, H::KeyLength>) -> Result<Option<V>> {
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
                    let key = H::convert_to_key(key_hash);
                    (key, v)
                }),
                &self.transport,
            )
            .await
    }

    pub async fn extend_by_hash<I>(&self, iter: I) -> Result<()>
    where
        I: IntoIterator<Item = (HashArray<H>, V)>,
    {
        self.root
            .batch_insert(
                iter.into_iter().map(|(k, v)| (H::convert_to_key(k), v)),
                &self.transport,
            )
            .await
    }

    pub async fn extend_by_key<I>(&self, iter: I) -> Result<()>
    where
        I: IntoIterator<Item = (GenericArray<H::Key, H::KeyLength>, V)>,
    {
        self.root
            .batch_insert(iter.into_iter(), &self.transport)
            .await
    }

    pub async fn reset_root(&mut self, new_root: Node<V, H>) {
        self.root = new_root;
    }
}
