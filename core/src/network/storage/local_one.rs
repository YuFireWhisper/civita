use dashmap::DashMap;

use crate::{
    crypto::Multihash,
    traits::{serializable, Serializable},
};

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Serializable(#[from] serializable::Error),
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
        T: Serializable,
    {
        self.records.insert(key, value.to_vec());
        Ok(())
    }

    pub fn put_batch<T, I>(&self, items: I) -> Result<()>
    where
        T: Serializable,
        I: IntoIterator<Item = (Multihash, T)>,
    {
        items
            .into_iter()
            .try_for_each(|(hash, value)| self.put(hash, value))
    }

    pub fn get<T>(&self, key: &Multihash) -> Result<Option<T>>
    where
        T: Serializable,
    {
        self.records
            .get(key)
            .map(|record| T::from_slice(record.value()).map_err(Error::from))
            .transpose()
    }
}
