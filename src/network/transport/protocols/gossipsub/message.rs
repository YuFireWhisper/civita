use libp2p::{
    gossipsub::{Event, MessageId},
    PeerId,
};
use log::error;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    crypto::tss::Signature,
    network::transport::{
        dispatcher::Keyed,
        protocols::gossipsub::{
            payload,
            signed_payload::{self, SignedPayload},
            Payload,
        },
    },
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Payload(#[from] payload::Error),

    #[error("{0}")]
    SignedPayload(#[from] signed_payload::Error),

    #[error("Source field is none")]
    MissingSource,

    #[error("Event is not a message")]
    NotMessageEvent,

    #[error("{0}")]
    Encode(#[from] bincode::error::EncodeError),

    #[error("{0}")]
    Decode(#[from] bincode::error::DecodeError),
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
    pub committee_signature: Option<Signature>,
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
            message_id,
            message,
            ..
        } = event
        {
            let source = message.source.ok_or(Error::MissingSource)?;
            let topic = message.topic.into_string();
            let signed_payload = SignedPayload::from_bytes(&message.data)?;
            let (payload, committee_signature) = signed_payload.take_payload_and_signature();

            Ok(Self {
                message_id,
                source,
                topic,
                payload,
                committee_signature,
            })
        } else {
            Err(Error::NotMessageEvent)
        }
    }
}

impl TryFrom<&Message> for Vec<u8> {
    type Error = Error;

    fn try_from(message: &Message) -> Result<Vec<u8>> {
        bincode::serde::encode_to_vec(message, bincode::config::standard()).map_err(Error::from)
    }
}

impl TryFrom<Message> for Vec<u8> {
    type Error = Error;

    fn try_from(message: Message) -> Result<Vec<u8>> {
        (&message).try_into()
    }
}

impl TryFrom<&[u8]> for Message {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        bincode::serde::decode_from_slice(value, bincode::config::standard())
            .map(|(m, _)| m)
            .map_err(Error::from)
    }
}

impl TryFrom<&Vec<u8>> for Message {
    type Error = Error;

    fn try_from(value: &Vec<u8>) -> Result<Self> {
        Message::try_from(value.as_slice())
    }
}

impl TryFrom<Vec<u8>> for Message {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self> {
        Message::try_from(value.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use libp2p::{gossipsub::MessageId, PeerId};

    use crate::network::transport::protocols::gossipsub::{Message, Payload};

    #[test]
    fn success_convert_with_vec() {
        const MESSAGE_ID: &[u8] = &[1, 2, 3, 4, 5];
        const TOPIC: &str = "test-topic";
        const PAYLOAD: &[u8] = &[1, 2, 3, 4, 5];

        let message = Message {
            message_id: MessageId::from(MESSAGE_ID),
            source: PeerId::random(),
            topic: TOPIC.to_string(),
            payload: Payload::Raw(PAYLOAD.to_vec()),
            committee_signature: None,
        };

        let message_vec: Vec<u8> = Message::try_into(message.clone()).unwrap();

        let message_from_vec = Message::try_from(message_vec.clone()).unwrap();
        let message_from_ref_vec = Message::try_from(&message_vec.clone()).unwrap();
        let message_from_bytes = Message::try_from(message_vec.as_slice()).unwrap();

        assert_eq!(message, message_from_vec);
        assert_eq!(message, message_from_ref_vec);
        assert_eq!(message, message_from_bytes);
    }
}
