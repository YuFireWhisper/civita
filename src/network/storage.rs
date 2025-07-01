use std::collections::{HashMap, HashSet};

use crate::{crypto::traits::hasher::Multihash, traits::Serializable};

#[async_trait::async_trait]
pub trait Storage {
    type Error;

    async fn get<T>(&self, key: &Multihash) -> Result<Option<T>, Self::Error>
    where
        T: Serializable + Sync + Send + 'static;
    async fn put<T>(&mut self, key: Multihash, value: T) -> Result<(), Self::Error>
    where
        T: Serializable + Sync + Send + 'static;
    async fn put_batch<T, I>(&mut self, items: I) -> Result<(), Self::Error>
    where
        T: Serializable + Sync + Send + 'static,
        I: IntoIterator<Item = (Multihash, T)> + Send + Sync;
}

pub struct CacheStorage<T, S> {
    storage: S,
    cache: HashMap<Multihash, T>,
    changes: HashSet<Multihash>,
}

impl<T, S> CacheStorage<T, S>
where
    T: Clone + Serializable + Sync + Send + 'static,
    S: Storage,
{
    pub fn new(storage: S) -> Self {
        Self {
            storage,
            cache: HashMap::new(),
            changes: HashSet::new(),
        }
    }

    pub async fn insert(&mut self, key: Multihash, value: T) {
        self.cache.insert(key, value);
        self.changes.insert(key);
    }

    pub async fn get(&mut self, key: &Multihash) -> Result<Option<&T>, S::Error> {
        if self.cache.contains_key(key) {
            return Ok(self.cache.get(key));
        }

        let Some(value) = self.storage.get::<T>(key).await? else {
            return Ok(None);
        };

        self.cache.insert(*key, value);

        Ok(Some(self.cache.get(key).unwrap()))
    }

    pub async fn commit(&mut self) -> Result<(), S::Error> {
        let mut items = Vec::new();

        for key in self.changes.drain() {
            if let Some(value) = self.cache.remove(&key) {
                items.push((key, value));
            }
        }

        if items.is_empty() {
            return Ok(());
        }

        self.storage.put_batch(items).await?;

        Ok(())
    }

    pub fn rollback(&mut self) {
        for key in self.changes.drain() {
            self.cache.remove(&key);
        }
    }
}
