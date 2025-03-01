use std::sync::Arc;

use libp2p::{gossipsub::MessageId, identity::Keypair, PeerId};
use serde::{Deserialize, Serialize};

use super::p2p_communication::P2PCommunication;

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
    use super::*;
    use std::collections::HashMap;

    const PEER_ADDR: &str = "/ip4/0.0.0.0/tcp/0";

    #[tokio::test]
    async fn test_new() {
        let keypair = Keypair::generate_ed25519();
        let p2p = P2PCommunication::new(keypair.clone(), PEER_ADDR.parse().unwrap()).unwrap();

        let handler = Arc::new(|_: ReceivedMessage<HashMap<String, String>>| {});
        let message_layer = MessageLayer::new(p2p, keypair.clone(), handler);

        assert_eq!(
            message_layer.peer_id,
            PeerId::from_public_key(&keypair.public())
        );
    }
}
