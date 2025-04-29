use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{crypto::tss::Signature, network::transport::protocols::kad::Payload};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(Error)]
pub enum Error {
    #[error("Failed to decode message: {0}")]
    Decode(#[from] serde_json::Error),
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
pub struct Message {
    pub payload: Payload,
    pub signature: Signature,
}

impl Message {
    pub fn new(payload: Payload, signature: Signature) -> Self {
        Self { payload, signature }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bytes.try_into()
    }

    pub fn to_vec(self) -> Result<Vec<u8>> {
        self.try_into()
    }
}

impl TryFrom<&[u8]> for Message {
    type Error = Error;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        serde_json::from_slice(value).map_err(Error::from)
    }
}

impl TryFrom<Message> for Vec<u8> {
    type Error = Error;

    fn try_from(message: Message) -> std::result::Result<Self, Self::Error> {
        serde_json::to_vec(&message).map_err(Error::from)
    }
}
