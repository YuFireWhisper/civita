use std::sync::Arc;

use civita_serialize::Serialize;

use crate::{crypto::Multihash, network::storage::local_one};

pub struct Storage {
    core: Arc<local_one::Storage>,
}

impl Storage {
    pub fn new(core: Arc<local_one::Storage>) -> Self {
        Self { core }
    }

    pub fn put<T>(&self, key: Multihash, value: T) -> Result<(), local_one::Error>
    where
        T: Serialize,
    {
        self.core.put(key, value)
    }

    pub fn put_batch<T, I>(&self, items: I) -> Result<(), local_one::Error>
    where
        T: Serialize,
        I: IntoIterator<Item = (Multihash, T)>,
    {
        self.core.put_batch(items)
    }

    pub fn get<T>(&self, key: &Multihash) -> Result<Option<T>, local_one::Error>
    where
        T: Serialize,
    {
        self.core.get(key)
    }
}
