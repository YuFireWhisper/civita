use std::sync::Arc;

use libp2p::{
    gossipsub::{self, MessageId},
    identity::Keypair,
    PeerId,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crypto::signature::{self, Signature};

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Signature(#[from] signature::Error),
    #[error("{0}")]
    Serde(#[from] serde_json::Error),
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid source")]
    InvalidSource,
    #[error("Invalid topic")]
    InvalidTopic,
    #[error("Invalid timestamp")]
    InvalidTimestamp,
}

type MessageResult<T> = Result<T, Error>;

#[derive(Serialize)]
struct SignableMessage<'a> {
    source: &'a PeerId,
    topic: &'a str,
    content: &'a [u8],
    timestamp: &'a u64,
}

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
    pub fn new(keypair: Arc<Keypair>, topic: &str, content: Vec<u8>) -> MessageResult<Self> {
        let source = PeerId::from_public_key(&keypair.public());
        let timestamp = chrono::Utc::now().timestamp() as u64;

        let signable = SignableMessage {
            source: &source,
            topic,
            content: &content,
            timestamp: &timestamp,
        };
        let signable_bytes = serde_json::to_vec(&signable)?;
        let signature = Signature::new(Arc::clone(&keypair)).sign(&signable_bytes)?;

        Ok(Self {
            message_id: None,
            source,
            topic: topic.to_string(),
            content,
            timestamp,
            signature: Some(signature),
        })
    }

    pub fn from_gossipsub_message(
        gossipsub_message: gossipsub::Message,
        keypair: Arc<Keypair>,
    ) -> MessageResult<Self> {
        let message: Self = serde_json::from_slice(&gossipsub_message.data)?;
        message.validate(&gossipsub_message, keypair)?;
        Ok(message)
    }

    pub fn validate(
        &self,
        gossipsub_message: &gossipsub::Message,
        keypair: Arc<Keypair>,
    ) -> MessageResult<()> {
        self.validate_source(gossipsub_message)?;
        self.validate_topic(gossipsub_message)?;
        self.validate_timestamp()?;
        self.validate_signature(keypair)?;

        Ok(())
    }

    fn validate_source(&self, gossipsub_message: &gossipsub::Message) -> MessageResult<()> {
        let source = gossipsub_message.source.ok_or(Error::InvalidSource)?;
        if self.source == source {
            Ok(())
        } else {
            Err(Error::InvalidSource)
        }
    }

    fn validate_topic(&self, gossipsub_message: &gossipsub::Message) -> MessageResult<()> {
        let topic = gossipsub_message.topic.as_str();
        if self.topic == topic {
            Ok(())
        } else {
            Err(Error::InvalidTopic)
        }
    }

    fn validate_timestamp(&self) -> MessageResult<()> {
        let now = chrono::Utc::now().timestamp() as u64;
        if self.timestamp <= now {
            Ok(())
        } else {
            Err(Error::InvalidTimestamp)
        }
    }

    fn validate_signature(&self, keypair: Arc<Keypair>) -> MessageResult<()> {
        let signable = SignableMessage::from(self);

        let message_bytes = serde_json::to_vec(&signable)?;
        let signature = self.signature.as_ref().ok_or(Error::InvalidSignature)?;

        let verifier = Signature::new(keypair);
        if verifier.verify(&message_bytes, signature) {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

impl<'a> From<&'a Message> for SignableMessage<'a> {
    fn from(message: &'a Message) -> Self {
        Self {
            source: &message.source,
            topic: &message.topic,
            content: &message.content,
            timestamp: &message.timestamp,
        }
    }
}

impl From<Message> for Vec<u8> {
    fn from(message: Message) -> Self {
        serde_json::to_vec(&message).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::Utc;
    use libp2p::{
        gossipsub::{self, TopicHash},
        identity::Keypair,
        PeerId,
    };

    use crate::network::{message::Error, transport::test_communication::TEST_TOPIC};

    use super::Message;

    const TEST_CONTENT: &[u8] = b"content";

    fn create_test_keypair() -> Arc<Keypair> {
        Arc::new(Keypair::generate_ed25519())
    }

    fn create_test_message(keypair: Arc<Keypair>) -> Message {
        Message::new(keypair, TEST_TOPIC, TEST_CONTENT.to_vec()).unwrap()
    }

    fn create_gossipsub_message(
        source: PeerId,
        topic: &str,
        content: Vec<u8>,
    ) -> gossipsub::Message {
        gossipsub::Message {
            source: Some(source),
            data: content,
            sequence_number: None,
            topic: TopicHash::from_raw(topic.to_string()),
        }
    }

    #[test]
    fn test_new() {
        let keypair = Arc::new(Keypair::generate_ed25519());
        let message = Message::new(keypair.clone(), TEST_TOPIC, TEST_CONTENT.to_vec()).unwrap();
        assert_eq!(message.source, PeerId::from_public_key(&keypair.public()));
    }

    #[test]
    fn test_validate_success() {
        let keypair = create_test_keypair();
        let message = create_test_message(keypair.clone());
        let gossip_message = create_gossipsub_message(
            message.source,
            &message.topic,
            serde_json::to_vec(&message).unwrap(),
        );

        let result = message.validate(&gossip_message, keypair);
        assert!(result.is_ok(), "{:?}", result);
    }

    #[test]
    fn test_validate_source_invalid() {
        let keypair = create_test_keypair();
        let message = create_test_message(keypair.clone());
        let different_keypair = create_test_keypair();
        let different_source = PeerId::from_public_key(&different_keypair.public());
        let gossip_message =
            create_gossipsub_message(different_source, &message.topic, message.content.clone());

        let result = message.validate(&gossip_message, keypair);
        assert!(matches!(result, Err(Error::InvalidSource)));
    }

    #[test]
    fn test_validate_source_none() {
        let keypair = create_test_keypair();
        let message = create_test_message(keypair.clone());
        let mut gossip_message =
            create_gossipsub_message(message.source, &message.topic, message.content.clone());
        gossip_message.source = None;

        let result = message.validate(&gossip_message, keypair);
        assert!(matches!(result, Err(Error::InvalidSource)));
    }

    #[test]
    fn test_validate_topic_invalid() {
        let keypair = create_test_keypair();
        let message = create_test_message(keypair.clone());
        let gossip_message =
            create_gossipsub_message(message.source, "different_topic", message.content.clone());

        let result = message.validate(&gossip_message, keypair);
        assert!(matches!(result, Err(Error::InvalidTopic)));
    }

    #[test]
    fn test_validate_timestamp_future() {
        let keypair = create_test_keypair();
        let mut message = create_test_message(keypair.clone());
        message.timestamp = (Utc::now().timestamp() as u64) + 1000;
        let gossip_message =
            create_gossipsub_message(message.source, &message.topic, message.content.clone());

        let result = message.validate(&gossip_message, keypair);
        assert!(matches!(result, Err(Error::InvalidTimestamp)));
    }

    #[test]
    fn test_validate_signature_invalid() {
        let keypair = create_test_keypair();
        let mut message = create_test_message(keypair.clone());
        // Tamper with signature
        message.signature = Some(vec![0; 64]); // Invalid signature
        let gossip_message =
            create_gossipsub_message(message.source, &message.topic, message.content.clone());

        let result = message.validate(&gossip_message, keypair);
        assert!(matches!(result, Err(Error::InvalidSignature)));
    }

    #[test]
    fn test_validate_signature_none() {
        let keypair = create_test_keypair();
        let mut message = create_test_message(keypair.clone());
        message.signature = None;
        let gossip_message =
            create_gossipsub_message(message.source, &message.topic, message.content.clone());

        let result = message.validate(&gossip_message, keypair);
        assert!(matches!(result, Err(Error::InvalidSignature)));
    }

    #[test]
    fn test_validate_with_different_keypair() {
        let keypair = create_test_keypair();
        let message = create_test_message(keypair.clone());
        let different_keypair = create_test_keypair();
        let gossip_message =
            create_gossipsub_message(message.source, &message.topic, message.content.clone());

        let result = message.validate(&gossip_message, different_keypair);
        assert!(matches!(result, Err(Error::InvalidSignature)));
    }

    #[test]
    fn test_from_gossipsub_message() {
        let keypair = create_test_keypair();
        let message = create_test_message(keypair.clone());
        let gossip_message = create_gossipsub_message(
            message.source,
            &message.topic,
            serde_json::to_vec(&message).unwrap(),
        );

        let result = Message::from_gossipsub_message(gossip_message, keypair);
        assert!(result.is_ok(), "{:?}", result);
    }
}
