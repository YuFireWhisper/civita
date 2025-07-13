use civita_serialize::Serialize;
use dashmap::DashMap;

use crate::crypto::Multihash;

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Serialization(#[from] civita_serialize::Error),
}

#[derive(Debug)]
#[derive(Default)]
pub struct Storage {
    records: DashMap<Multihash, Vec<u8>>,
}

impl Storage {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put<T>(&self, key: Multihash, value: T) -> Result<()>
    where
        T: Serialize,
    {
        self.records.insert(key, value.to_vec());
        Ok(())
    }

    pub fn put_batch<T, I>(&self, items: I) -> Result<()>
    where
        T: Serialize,
        I: IntoIterator<Item = (Multihash, T)>,
    {
        items
            .into_iter()
            .try_for_each(|(hash, value)| self.put(hash, value))
    }

    pub fn get<T>(&self, key: &Multihash) -> Result<Option<T>>
    where
        T: Serialize,
    {
        self.records
            .get(key)
            .map(|record| T::from_slice(record.value()).map_err(Error::from))
            .transpose()
    }
}
