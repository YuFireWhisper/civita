use bincode::{config, error::EncodeError, serde::encode_to_vec};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(Error)]
pub enum Error {
    #[error("Failed to encode payload: {0}")]
    Encode(#[from] EncodeError),
}

#[derive(Debug)]
#[derive(Clone)]
#[derive(Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
pub enum Payload {
    PeerInfo { peer_id: PeerId, pub_key: Vec<u8> },
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
