use libp2p::kad::RecordKey;
use serde::{Deserialize, Serialize};

use crate::traits::{byteable, Byteable};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Byteable(#[from] byteable::Error),
}

#[derive(Debug)]
#[derive(Serialize, Deserialize)]
pub enum Key {
    /// The PeerId of the resident
    Resident(libp2p::PeerId),

    /// The hash of the proposal
    Proposal([u8; 32]),

    /// Committee epoch
    /// It will not include the current epoch
    CommitteeInfo(u64),

    /// Current Committee info
    CurrentCommitteeInfo,

    /// For testing
    Raw,
}

impl Key {
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
