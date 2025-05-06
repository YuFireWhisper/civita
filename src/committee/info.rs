use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::{crypto::algebra::Point, network::transport::protocols::kad, utils::IndexedMap};

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("Failed to encode: {0}")]
    Encode(#[from] bincode::error::EncodeError),

    #[error("Failed to decode: {0}")]
    Decode(#[from] bincode::error::DecodeError),

    #[error("Payload variant is not info")]
    NotInfoVariant,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
pub struct Info {
    pub epoch: u64,

    pub members: IndexedMap<libp2p::PeerId, ()>,

    pub public_key: Point,

    pub end: SystemTime,
}

impl Info {
    pub fn new(
        epoch: u64,
        members: IndexedMap<libp2p::PeerId, ()>,
        public_key: Point,
        end: SystemTime,
    ) -> Self {
        Self {
            epoch,
            members,
            public_key,
            end,
        }
    }
}

impl TryFrom<&Info> for Vec<u8> {
    type Error = Error;

    fn try_from(info: &Info) -> Result<Self, Self::Error> {
        bincode::serde::encode_to_vec(info, bincode::config::standard()).map_err(Error::from)
    }
}

impl TryFrom<&[u8]> for Info {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        bincode::serde::decode_from_slice(bytes, bincode::config::standard())
            .map(|(info, _)| info)
            .map_err(Error::from)
    }
}

impl TryFrom<kad::Payload> for Info {
    type Error = Error;

    fn try_from(payload: kad::Payload) -> Result<Self, Self::Error> {
        if let kad::Payload::Committee(info) = payload {
            Ok(info)
        } else {
            Err(Error::NotInfoVariant)
        }
    }
}
