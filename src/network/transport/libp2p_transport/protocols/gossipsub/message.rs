use libp2p::{
    gossipsub::{Event, MessageId},
    PeerId,
};
use log::error;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    crypto::tss::Signature,
    network::transport::libp2p_transport::{
        dispatcher::Keyed,
        protocols::gossipsub::{payload, Payload},
    },
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("Sequence number is missing")]
    MissingSequenceNumber,

    #[error("Event is not a valid message")]
    InvalidMessage,

    #[error("{0}")]
    Payload(#[from] payload::Error),

    #[error("Encode error: {0}")]
    Encode(#[from] bincode::error::EncodeError),

    #[error("Decode error: {0}")]
    Decode(#[from] bincode::error::DecodeError),

    #[error("Payload requires signature")]
    MissingSignature,

    #[error("Payload does not require signature")]
    SignatureNotRequired,
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
pub struct Message {
    pub message_id: MessageId,
    pub source: PeerId,
    pub topic: String,
    pub payload: Payload,
    pub sequence_number: u64,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
pub(super) struct TransportMessage {
    pub payload: Payload,
    pub signature: Option<Signature>,
}

impl Message {
    pub fn try_from_gossipsub_event(event: Event) -> Result<Self> {
        Self::try_from(event)
    }
}

impl TransportMessage {
    pub fn new(payload: Payload, signature: Option<Signature>) -> Result<Self> {
        let message = TransportMessage { payload, signature };
        message.validate()?;
        Ok(message)
    }

    pub fn validate(&self) -> Result<()> {
        if self.payload.need_signature() && self.signature.is_none() {
            return Err(Error::MissingSignature);
        }
        if !self.payload.need_signature() && self.signature.is_some() {
            return Err(Error::SignatureNotRequired);
        }
        Ok(())
    }

    pub fn to_vec(&self) -> Result<Vec<u8>> {
        self.try_into()
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

impl TryFrom<&TransportMessage> for Vec<u8> {
    type Error = Error;

    fn try_from(message: &TransportMessage) -> Result<Self> {
        bincode::serde::encode_to_vec(message, bincode::config::standard()).map_err(Error::from)
    }
}

impl TryFrom<&[u8]> for TransportMessage {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        let msg: TransportMessage =
            bincode::serde::decode_from_slice(bytes, bincode::config::standard())
                .map(|(message, _)| message)?;

        msg.validate()?;

        Ok(msg)
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
