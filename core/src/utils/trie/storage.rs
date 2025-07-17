use crate::crypto::Multihash;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum StorageError {}

pub trait Storage {
    fn get(&self, hash: &Multihash) -> Result<Option<Vec<u8>>, StorageError>;

    fn put(&mut self, hash: Multihash, data: Vec<u8>) -> Result<(), StorageError>;

    fn batch_put<I>(&mut self, entries: I) -> Result<(), StorageError>
    where
        I: IntoIterator<Item = (Multihash, Vec<u8>)>,
    {
        for (hash, data) in entries {
            self.put(hash, data)?;
        }
        Ok(())
    }

    fn delete(&mut self, hash: &Multihash) -> Result<(), StorageError>;

    fn has(&self, hash: &Multihash) -> Result<bool, StorageError>;
}
