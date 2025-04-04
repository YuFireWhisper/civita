use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{crypto::dkg::Data, network::transport::libp2p_transport::protocols::kad::Payload};

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
    pub signature: Data,
}

impl Message {
    pub fn new(payload: Payload, signature: Data) -> Self {
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

#[cfg(test)]
mod tests {
    use crate::crypto::dkg::classic::signature::SignatureBytes;

    use super::*;

    const PAYLOAD: &[u8] = &[1, 2, 3];

    fn create_payload() -> Payload {
        Payload::Raw(PAYLOAD.to_vec())
    }

    #[test]
    fn test_new() {
        let payload = create_payload();
        let signature = SignatureBytes::random();
        let data = Data::Classic(signature);

        let result = Message::new(payload.clone(), data.clone());

        assert_eq!(result.payload, payload);
        assert_eq!(result.signature, data);
    }
}
