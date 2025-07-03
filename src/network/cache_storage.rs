use std::{collections::HashSet, sync::Arc};

use dashmap::{mapref::one::Ref, DashMap};

use crate::{
    crypto::Multihash,
    network::kad::{self, Kad},
    traits::Serializable,
};

pub struct CacheStorage<T> {
    storage: Arc<Kad>,
    cache: DashMap<Multihash, T>,
    changes: HashSet<Multihash>,
}

impl<T> CacheStorage<T>
where
    T: Serializable + Sync + Send + 'static,
{
    pub fn new(storage: Arc<Kad>) -> Self {
        Self {
            storage,
            cache: DashMap::new(),
            changes: HashSet::new(),
        }
    }

    pub fn insert(&mut self, key: Multihash, value: T) {
        self.cache.insert(key, value);
        self.changes.insert(key);
    }

    pub async fn get(&self, key: &Multihash) -> Result<Option<Ref<Multihash, T>>, kad::Error> {
        if let Some(value) = self.cache.get(key) {
            return Ok(Some(value));
        }

        let Some(value) = self.storage.get::<T>(key).await? else {
            return Ok(None);
        };

        self.cache.insert(*key, value);

        Ok(Some(self.cache.get(key).unwrap()))
    }

    pub async fn commit(&mut self) -> Result<(), kad::Error> {
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
