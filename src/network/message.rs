use libp2p::{gossipsub::{self, MessageId}, PeerId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Serde(#[from] serde_json::Error),
    #[error("Invalid timestamp")]
    InvalidTimestamp,
}

type MessageResult<T> = Result<T, Error>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MessagePayload {
    InitRandom {
        threshold: usize,
        total_residents: usize,
    },
    PartialRandom {
        response_for: MessageId,
        share: Vec<u8>,
    },
    RandomValue {
        response_for: MessageId,
        value: Vec<u8>,
        signature: Vec<u8>,
    },
    RawData { data: Vec<u8> },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Message {
    pub message_id: Option<MessageId>,
    pub source: Option<PeerId>,
    pub topic: String,
    pub payload: MessagePayload,
    pub timestamp: u64,
}

impl Message {
    pub fn new(topic: &str, payload: MessagePayload) -> Self {
        let message_id = None;
        let source = None;
        let topic = topic.to_string();
        let timestamp = chrono::Utc::now().timestamp() as u64;

        Self {
            message_id,
            source,
            topic,
            payload,
            timestamp,
        }
    }

    fn from_gossipsub_message(gossipsub_message: gossipsub::Message) -> MessageResult<Self> {
        let message: Self = serde_json::from_slice(&gossipsub_message.data)?;
        message.validate()?;
        Ok(message)
    }

    fn validate(&self) -> MessageResult<()> {
        self.validate_timestamp()?;

        Ok(())
    }

    fn validate_timestamp(&self) -> MessageResult<()> {
        let now = chrono::Utc::now().timestamp() as u64;
        if self.timestamp <= now {
            Ok(())
        } else {
            Err(Error::InvalidTimestamp)
        }
    }

    pub fn set_message_id(&mut self, message_id: MessageId) {
        self.message_id = Some(message_id);
    }
}

impl From<Message> for Vec<u8> {
    fn from(message: Message) -> Self {
        serde_json::to_vec(&message).unwrap()
    }
}

impl TryFrom<gossipsub::Message> for Message {
    type Error = Error;

    fn try_from(gossipsub_message: gossipsub::Message) -> MessageResult<Self> {
        Self::from_gossipsub_message(gossipsub_message)
    }
}

#[cfg(test)]
mod tests {
    use crate::network::{
        message::{Message, MessagePayload},
        transport::test_communication::TEST_TOPIC,
    };

    const TEST_CONTENT: &[u8] = b"content";

    #[test]
    fn test_new() {
        let payload = MessagePayload::RawData {
            data: TEST_CONTENT.to_vec(),
        };
        let message = Message::new(TEST_TOPIC, payload.clone());

        assert_eq!(message.topic, TEST_TOPIC);
        assert_eq!(message.payload, payload);
        assert!(message.timestamp > 0);
    }
}
