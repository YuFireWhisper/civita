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

    #[error("Signature verification failed")]
    SignatureVerificationFailed,
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
    pub sequence_number: u64,
    pub payload: Payload,
    pub signature: Option<Signature>,
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
            let sequence_number = message
                .sequence_number
                .ok_or(Error::MissingSequenceNumber)?;
            let transport_message = TransportMessage::try_from(message.data.as_slice())?;
            let payload = transport_message.payload;
            let signature = transport_message.signature;

            Ok(Message {
                message_id,
                source,
                topic,
                sequence_number,
                payload,
                signature,
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
mod tests {
    use libp2p::gossipsub::{self, IdentTopic, MessageId};

    use crate::{
        crypto::{
            primitives::algebra::{Point, Scalar},
            tss::{schnorr, Signature},
        },
        network::transport::libp2p_transport::protocols::gossipsub::{
            Message, Payload, TransportMessage,
        },
    };

    const TEST_TOPIC: &str = "test_topic";
    const TEST_SEQUENCE_NUMBER: u64 = 1;
    const TEST_PAYLOAD: &[u8] = b"test_payload";
    const MESSAGE_ID: &[u8] = b"test-message-id";

    fn create_signature() -> Option<Signature> {
        Some(Signature::Schnorr(schnorr::signature::Signature::new(
            Scalar::secp256k1_random(),
            Point::secp256k1_zero(),
        )))
    }

    fn create_gossipsub_event(
        payload: Payload,
        signature: Option<Signature>,
        sequence_number: Option<u64>,
    ) -> gossipsub::Event {
        let message_id = MessageId::from(MESSAGE_ID);
        let source = libp2p::PeerId::random();
        let transport_message = TransportMessage::new(payload, signature).unwrap();

        gossipsub::Event::Message {
            propagation_source: source,
            message_id,
            message: gossipsub::Message {
                source: Some(source),
                topic: IdentTopic::new(TEST_TOPIC).hash(),
                sequence_number,
                data: transport_message.to_vec().unwrap(),
            },
        }
    }

    #[test]
    fn success_when_all_fields_are_present() {
        let payload = Payload::RawWithSignature {
            raw: TEST_PAYLOAD.to_vec(),
            signature: Some(create_signature().unwrap()),
        };

        let result = TransportMessage::new(payload, create_signature());

        assert!(
            result.is_ok(),
            "Failed to create TransportMessage: {:?}",
            result
        );
    }

    #[test]
    fn fail_when_signature_is_missing() {
        let payload = Payload::RawWithSignature {
            raw: TEST_PAYLOAD.to_vec(),
            signature: None,
        };

        let result = TransportMessage::new(payload, None);

        assert!(
            result.is_err(),
            "Expected error when signature is missing, but got: {:?}",
            result
        );
    }

    #[test]
    fn success_when_signature_is_not_required() {
        let payload = Payload::Raw(TEST_PAYLOAD.to_vec());

        let result = TransportMessage::new(payload, None);

        assert!(
            result.is_ok(),
            "Failed to create TransportMessage: {:?}",
            result
        );
    }

    #[test]
    fn fail_when_signature_is_not_required() {
        let payload = Payload::Raw(TEST_PAYLOAD.to_vec());

        let result = TransportMessage::new(payload, create_signature());

        assert!(
            result.is_err(),
            "Expected error when signature is not required, but got: {:?}",
            result
        );
    }

    #[test]
    fn success_convert_from_gossipsub_event() {
        let payload = Payload::RawWithSignature {
            raw: TEST_PAYLOAD.to_vec(),
            signature: Some(create_signature().unwrap()),
        };
        let event = create_gossipsub_event(
            payload.clone(),
            create_signature(),
            Some(TEST_SEQUENCE_NUMBER),
        );

        let result = Message::try_from_gossipsub_event(event);

        assert!(
            result.is_ok(),
            "Failed to convert from gossipsub event: {:?}",
            result
        );
        let message = result.unwrap();
        assert_eq!(message.topic, TEST_TOPIC);
        assert_eq!(message.sequence_number, TEST_SEQUENCE_NUMBER);
        assert_eq!(message.payload, payload);
    }
}
