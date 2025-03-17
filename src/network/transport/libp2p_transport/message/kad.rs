pub mod payload;

use libp2p::identity::Keypair;
pub use payload::Payload;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct Message {
    payload: Payload,
    signature: Vec<u8>,
}

impl Message {
    pub fn new(payload: Payload, keypair: &Keypair) -> Self {
        let signature = vec![]; // TODO: sign payload with keypair

        Self { payload, signature }
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

    #[test]
    fn test_new() {
        let payload = create_payload();
        let keypair = create_keypair();

        let result = Message::new(payload.clone(), &keypair);

        assert_eq!(result.payload, payload);
    }
}
