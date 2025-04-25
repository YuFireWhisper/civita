use serde::{Deserialize, Serialize};

use crate::crypto::{index_map::IndexedMap, keypair::PublicKey, primitives::algebra::Point};

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("Failed to encode: {0}")]
    Encode(#[from] bincode::error::EncodeError),

    #[error("Failed to decode: {0}")]
    Decode(#[from] bincode::error::DecodeError),
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
pub struct Info {
    pub epoch: u64,
    pub members: IndexedMap<libp2p::PeerId, PublicKey>,
    pub public_key: Point,
}

impl Info {
    pub fn new(
        epoch: u64,
        members: IndexedMap<libp2p::PeerId, PublicKey>,
        public_key: Point,
    ) -> Self {
        Self {
            epoch,
            members,
            public_key,
        }
    }

    pub fn to_vec(&self) -> Result<Vec<u8>, Error> {
        self.try_into()
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        Self::try_from(bytes)
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

#[cfg(test)]
mod tests {
    use crate::{committee::info::Info, crypto::primitives::algebra::Point};

    #[test]
    fn convert_success() {
        let info = Info::new(1, Default::default(), Point::secp256k1_zero());
        let bytes = info.to_vec().unwrap();
        let decoded_info = Info::from_slice(&bytes).unwrap();
        assert_eq!(info, decoded_info);
    }
}
