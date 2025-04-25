use bincode::{config, error::EncodeError, serde::encode_to_vec};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crypto::primitives::algebra::Point;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(Error)]
pub enum Error {
    #[error("Failed to encode payload: {0}")]
    Encode(#[from] EncodeError),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

#[derive(Debug)]
#[derive(Clone)]
#[derive(Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
pub enum Payload {
    CommitteePubKey(Point),
    // For testing
    Raw(Vec<u8>),
}

impl Payload {
    pub fn to_vec(&self) -> Result<Vec<u8>> {
        self.try_into().map_err(Error::from)
    }
}

impl Default for Payload {
    fn default() -> Self {
        Payload::Raw(vec![])
    }
}

impl TryFrom<&Payload> for Vec<u8> {
    type Error = EncodeError;

    fn try_from(payload: &Payload) -> std::result::Result<Self, Self::Error> {
        encode_to_vec(payload, config::standard())
    }
}

impl TryFrom<libp2p::kad::Record> for Payload {
    type Error = Error;

    fn try_from(record: libp2p::kad::Record) -> std::result::Result<Self, Self::Error> {
        Ok(serde_json::from_slice(&record.value)?)
    }
}
