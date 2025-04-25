use libp2p::kad::RecordKey;
use serde::{Deserialize, Serialize};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

#[derive(Debug)]
#[derive(Serialize, Deserialize)]
pub enum Key {
    CommitteePubKey(u64),
}

impl Key {
    pub fn to_vec(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(Error::from)
    }

    pub fn to_storage_key(&self) -> Result<libp2p::kad::RecordKey> {
        self.try_into()
    }
}

impl TryFrom<&Key> for RecordKey {
    type Error = Error;

    fn try_from(key: &Key) -> std::result::Result<Self, Self::Error> {
        let key_bytes = key.to_vec()?;
        Ok(libp2p::kad::RecordKey::new(&key_bytes))
    }
}
