use libp2p::{gossipsub::MessageId, identity::Keypair, PeerId};
use serde::{Deserialize, Serialize};

use crate::crypto::signature::Signature;

#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
    pub message_id: Option<MessageId>,
    pub source: PeerId,
    pub topic: String,
    pub content: Vec<u8>,
    pub timestamp: u64,
    pub signature: Option<Vec<u8>>,
}

impl Message {
    pub fn new(keypair: Keypair, topic: &str, content: Vec<u8>) -> Result<Self, String> {
        let source = PeerId::from_public_key(&keypair.public());
        let timestamp = chrono::Utc::now().timestamp() as u64;

        let mut message = Self {
            message_id: None,
            source,
            topic: topic.to_string(),
            content,
            timestamp,
            signature: None,
        };

        let signature = Signature::new(keypair).sign(&serde_json::to_vec(&message).unwrap())?;
        message.signature = Some(signature);

        Ok(message)
    }
}

#[cfg(test)]
mod tests {
    use libp2p::{identity::Keypair, PeerId};

    use crate::network::transport::test_communication::TEST_TOPIC;

    use super::Message;

    const TEST_CONTENT: &[u8] = b"content";

    #[test]
    fn test_new() {
        let keypair = Keypair::generate_ed25519();

        let message = Message::new(keypair.clone(), TEST_TOPIC, TEST_CONTENT.to_vec()).unwrap();

        assert_eq!(message.source, PeerId::from_public_key(&keypair.public()));
    }
}
