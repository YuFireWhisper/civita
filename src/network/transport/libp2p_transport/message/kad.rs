pub mod payload;

use libp2p::identity::{Keypair, SigningError};
use serde::{Deserialize, Serialize};

pub use payload::Payload;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to serialize message: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("Failed to sign message: {0}")]
    Sign(#[from] SigningError),
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct Message {
    payload: Payload,
    signature: Vec<u8>,
}

impl Message {
    pub fn new(payload: Payload, keypair: &Keypair) -> Result<Self> {
        let signature = keypair.sign(&serde_json::to_vec(&payload)?)?;

        Ok(Self { payload, signature })
    }
}

#[cfg(test)]
mod tests {
    use libp2p::identity::Keypair;

    use crate::network::transport::libp2p_transport::message::kad::{Message, Payload};

    const PAYLOAD: &[u8] = &[1, 2, 3];

    fn create_payload() -> Payload {
        Payload::Raw(PAYLOAD.to_vec())
    }

    fn create_keypair() -> Keypair {
        Keypair::generate_ed25519()
    }

    fn verify_signature(payload: &Payload, signature: &[u8], keypair: &Keypair) -> bool {
        let payload = serde_json::to_vec(payload).unwrap();
        keypair.public().verify(&payload, signature)
    }

    #[test]
    fn test_new() {
        let payload = create_payload();
        let keypair = create_keypair();

        let message = Message::new(payload.clone(), &keypair).unwrap();
        let is_valid = verify_signature(&payload, &message.signature, &keypair);

        assert_eq!(message.payload, payload);
        assert!(is_valid);
    }
}
