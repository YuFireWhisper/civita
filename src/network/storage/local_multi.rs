use crate::{crypto::Multihash, network::storage::local_one, traits::Serializable};

pub struct Storage {
    core: local_one::Storage,
}

impl Storage {
    pub fn new(core: local_one::Storage) -> Self {
        Self { core }
    }

    pub fn put<T>(&self, key: Multihash, value: T) -> Result<(), local_one::Error>
    where
        T: Serializable,
    {
        self.core.put(key, value)
    }

    pub fn put_batch<T, I>(&self, items: I) -> Result<(), local_one::Error>
    where
        T: Serializable,
        I: IntoIterator<Item = (Multihash, T)>,
    {
        self.core.put_batch(items)
    }

    pub fn get<T>(&self, key: &Multihash) -> Result<Option<T>, local_one::Error>
    where
        T: Serializable,
    {
        self.core.get(key)
    }
}
