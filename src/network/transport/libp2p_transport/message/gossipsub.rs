pub mod payload;

use chrono::{DateTime, Utc};
use libp2p::{
    gossipsub::{self, MessageId},
    PeerId,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use payload::Payload;

pub const TIMESTAMP_TOLERANCE_SECONDS: u64 = 30;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Serde(#[from] serde_json::Error),
    #[error("Missing message ID")]
    MissingMessageId,
    #[error("Missing source peer ID")]
    MissingSourcePeerId,
    #[error("Invalid timestamp")]
    InvalidTimestamp,
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct Message {
    pub message_id: Option<MessageId>,
    pub source: Option<PeerId>,
    pub topic: String,
    pub payload: Payload,
    pub timestamp: i64,
}

impl Message {
    pub fn new(topic: &str, payload: Payload) -> Self {
        let message_id = None;
        let source = None;
        let topic = topic.to_string();
        let timestamp = Utc::now().timestamp();

        Self {
            message_id,
            source,
            topic,
            payload,
            timestamp,
        }
    }

    fn from_gossipsub_message(gossipsub_message: gossipsub::Message) -> Result<Self> {
        let message: Self = serde_json::from_slice(&gossipsub_message.data)?;
        message.validate()?;
        Ok(message)
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_message_id()?;
        self.validate_source()?;
        self.validate_timestamp()?;

        Ok(())
    }

    fn validate_message_id(&self) -> Result<()> {
        if self.message_id.is_none() {
            return Err(Error::MissingMessageId);
        }

        Ok(())
    }

    fn validate_source(&self) -> Result<()> {
        if self.source.is_none() {
            return Err(Error::MissingSourcePeerId);
        }

        Ok(())
    }

    fn validate_timestamp(&self) -> Result<()> {
        let now = Utc::now();
        let past_time =
            DateTime::from_timestamp(self.timestamp, 0).ok_or(Error::InvalidTimestamp)?;
        let diff = now - past_time;

        if diff.num_seconds() > TIMESTAMP_TOLERANCE_SECONDS as i64 {
            return Err(Error::InvalidTimestamp);
        }

        Ok(())
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

    fn try_from(gossipsub_message: gossipsub::Message) -> Result<Self> {
        Self::from_gossipsub_message(gossipsub_message)
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use libp2p::{gossipsub::MessageId, PeerId};

    use crate::network::transport::libp2p_transport::message::gossipsub::{
        Message, Payload, TIMESTAMP_TOLERANCE_SECONDS,
    };

    const TOPIC: &str = "TOPIC";
    const PAYLOAD: &[u8] = &[1, 2, 3];
    const MESSAGE_ID: &str = "MESSAGE_ID";

    struct TestMessage {
        message: Message,
        created_payload: Payload,
        created_at: i64,
    }

    impl TestMessage {
        fn new() -> Self {
            let payload = create_payload();
            let message = Message::new(TOPIC, payload.clone());
            let created_at = Utc::now().timestamp();

            Self {
                message,
                created_payload: payload,
                created_at,
            }
        }

        fn with_message_id(mut self) -> Self {
            let message_id = create_message_id();

            self.message.message_id = Some(message_id);
            self
        }

        fn with_source(mut self) -> Self {
            let source = create_peer_id();

            self.message.source = Some(source);
            self
        }
    }

    fn create_payload() -> Payload {
        Payload::Raw(PAYLOAD.to_vec())
    }

    fn create_message_id() -> MessageId {
        MessageId::from(MESSAGE_ID)
    }

    fn create_peer_id() -> PeerId {
        PeerId::random()
    }

    #[test]
    fn test_new() {
        let message = TestMessage::new();
        let expected_payload = message.created_payload;
        let expected_timestamp = message.created_at;

        let result = message.message;

        assert!(result.message_id.is_none());
        assert!(result.source.is_none());
        assert_eq!(result.topic, TOPIC);
        assert_eq!(result.payload, expected_payload);
        assert_eq!(result.timestamp, expected_timestamp);
    }

    #[test]
    fn test_validate_success() {
        let message = TestMessage::new().with_message_id().with_source().message;

        let result = message.validate();

        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_missing_message_id() {
        let message = TestMessage::new().with_source().message; // Missing message ID

        let result = message.validate();

        assert!(result.is_err());
    }

    #[test]
    fn test_validate_missing_source() {
        let message = TestMessage::new().with_message_id().message; // Missing source

        let result = message.validate();

        assert!(result.is_err());
    }

    #[test]
    fn test_validate_invalid_timestamp() {
        let mut message = TestMessage::new().with_message_id().with_source().message;
        message.timestamp = Utc::now().timestamp() - 2 * (TIMESTAMP_TOLERANCE_SECONDS as i64);

        let result = message.validate();

        assert!(result.is_err());
    }
}
