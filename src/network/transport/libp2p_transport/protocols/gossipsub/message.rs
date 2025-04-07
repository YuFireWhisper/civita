use libp2p::{
    gossipsub::{Event, MessageId},
    PeerId,
};
use log::error;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::network::transport::libp2p_transport::{
    dispatcher::Keyed, protocols::gossipsub::Payload,
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Serde(#[from] serde_json::Error),
    #[error("Sequence number is missing")]
    MissingSequenceNumber,
    #[error("Event is not a valid message")]
    InvalidMessage,
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct Message {
    pub message_id: MessageId,
    pub source: PeerId,
    pub topic: String,
    pub payload: Payload,
    pub sequence_number: u64,
}

impl Message {
    pub fn try_from_gossipsub_event(event: Event) -> Result<Self> {
        Self::try_from(event)
    }
}

impl Keyed<String> for Message {
    fn key(&self) -> &String {
        &self.topic
    }
}

impl TryFrom<libp2p::gossipsub::Event> for Message {
    type Error = Error;

    fn try_from(event: Event) -> Result<Self> {
        if let Event::Message {
            propagation_source,
            message_id,
            message,
        } = event
        {
            let source = propagation_source;
            let topic = message.topic.into_string();
            let payload: Payload = Payload::try_from(message.data)?;
            let sequence_number = message
                .sequence_number
                .ok_or(Error::MissingSequenceNumber)?;

            Ok(Message {
                message_id,
                source,
                topic,
                payload,
                sequence_number,
            })
        } else {
            Err(Error::InvalidMessage)
        }
    }
}

#[cfg(test)]
pub mod mock_message {
    use super::*;

    use libp2p::gossipsub::MessageId;
    use libp2p::PeerId;

    const TOPIC: &str = "TOPIC";
    const PAYLOAD: &[u8] = &[1, 2, 3];
    const SEQUENCE_NUMBER: u64 = 1;

    pub fn create_message() -> Message {
        let message_id = MessageId::from("MESSAGE_ID");
        let source = PeerId::random();
        let topic = TOPIC.to_string();
        let payload = Payload::Raw(PAYLOAD.to_vec());
        let sequence_number = SEQUENCE_NUMBER;

        Message {
            message_id,
            source,
            topic,
            payload,
            sequence_number,
        }
    }
}
