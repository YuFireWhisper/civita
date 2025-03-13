use chrono::{DateTime, Utc};
use libp2p::{
    gossipsub::{self, MessageId},
    PeerId,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::Payload;

pub const TIMESTAMP_TOLERANCE_SECONDS: u64 = 30;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Serde(#[from] serde_json::Error),
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
        let timestamp = chrono::Utc::now().timestamp();

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

    fn validate(&self) -> Result<()> {
        self.validate_timestamp()?;

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
