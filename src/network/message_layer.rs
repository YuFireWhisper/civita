use std::sync::Arc;

use libp2p::{
    gossipsub::MessageId,
    identity::{self, Keypair},
    PeerId,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::p2p_communication::{self, P2PCommunication};

#[derive(Debug, Error)]
pub enum MessageLayerError {
    #[error("Failed to serialize message: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Failed to sign message: {0}")]
    Signing(#[from] identity::SigningError),
    #[error("Failed to publish message: {0}")]
    Publishing(#[from] p2p_communication::P2PCommunicationError),
}

type MessageLayerResult<T> = std::result::Result<T, MessageLayerError>;

pub struct MessageLayer<T: Serialize> {
    p2p: P2PCommunication,
    keypair: Keypair,
    peer_id: PeerId,
    handler: Arc<MessageHandler<T>>,
}

impl<T: Serialize> MessageLayer<T> {
    pub fn new(p2p: P2PCommunication, keypair: Keypair, handler: Arc<MessageHandler<T>>) -> Self {
        let peer_id = PeerId::from_public_key(&keypair.public());
        Self {
            p2p,
            keypair,
            peer_id,
            handler,
        }
    }

    pub fn send(&mut self, content: T, topic: &str) -> MessageLayerResult<()> {
        let timestamp = chrono::Utc::now().timestamp() as u64;

        let mut message = SentMessage {
            content,
            timestamp,
            signature: Vec::new(),
        };

        let serialized_message = serde_json::to_vec(&message)?;
        let signature = self.keypair.sign(&serialized_message)?;

        message.signature = signature.to_vec();

        let data = serde_json::to_vec(&message)?;

        self.p2p.publish(topic, data)?;

        Ok(())
    }
}

type MessageHandler<T> = dyn Fn(ReceivedMessage<T>) + Send + Sync;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentMessage<T: Serialize> {
    pub content: T,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ReceivedMessage<T> {
    pub content: T,
    pub timestamp: u64,
    pub signature: Vec<u8>,
    pub message_id: MessageId,
    pub source: PeerId,
    pub topic: String,
}

#[cfg(test)]
mod tests {
    use crate::network::p2p_communication::test_communication::{TestCommunication, TEST_TOPIC};

    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_new() {
        let communication = TestCommunication::new().await.unwrap();
        let handler = Arc::new(|_: ReceivedMessage<HashMap<String, String>>| {});

        let message_layer = MessageLayer::new(communication.p2p, communication.keypair, handler);

        assert_eq!(message_layer.peer_id, communication.peer_id);
    }

    #[tokio::test]
    async fn test_send() {
        let mut node1 = TestCommunication::new().await.unwrap();
        let mut node2 = TestCommunication::new().await.unwrap();

        node1
            .establish_gossipsub_connection(&mut node2)
            .await
            .unwrap();

        let handler = Arc::new(|_: ReceivedMessage<HashMap<String, String>>| {});
        let mut message_layer = MessageLayer::new(node1.p2p, node1.keypair, handler);

        let content = HashMap::new();

        let result = message_layer.send(content, TEST_TOPIC);

        assert!(result.is_ok(), "Failed to send message: {:?}", result);
    }
}
