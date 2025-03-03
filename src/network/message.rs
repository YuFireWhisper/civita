use libp2p::gossipsub::{self, MessageId};
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Message {
    pub message_id: Option<MessageId>,
    pub topic: String,
    pub content: Vec<u8>,
    pub timestamp: u64,
}

impl Message {
    pub fn new(topic: &str, content: Vec<u8>) -> Self {
        let message_id = None;
        let topic = topic.to_string();
        let timestamp = chrono::Utc::now().timestamp() as u64;

        Self {
            message_id,
            topic,
            content,
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
    use crate::network::{message::Message, transport::test_communication::TEST_TOPIC};

    const TEST_CONTENT: &[u8] = b"content";

    #[test]
    fn test_new() {
        let message = Message::new(TEST_TOPIC, TEST_CONTENT.to_vec());

        assert_eq!(message.topic, TEST_TOPIC);
        assert_eq!(message.content, TEST_CONTENT);
        assert!(message.timestamp > 0);
    }
}
