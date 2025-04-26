use libp2p::gossipsub::Event;
use log::error;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    crypto::{keypair::ResidentSignature, tss::CommitteeSignature},
    identity::resident_id::ResidentId,
    network::transport::libp2p_transport::protocols::gossipsub::{MessageId, Payload},
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("Encode error: {0}")]
    Encode(#[from] bincode::error::EncodeError),

    #[error("Decode error: {0}")]
    Decode(#[from] bincode::error::DecodeError),

    #[error("Require MessageId")]
    RequireMessageId,

    #[error("Require Source")]
    RequireSource,

    #[error("Require Topic")]
    RequireTopic,

    #[error("Require Payload")]
    RequirePayload,

    #[error("Require Resident Signature")]
    RequireResidentSignature,

    #[error("Require Signature")]
    RequireSignature,

    #[error("Payload does not require signature")]
    NotRequiredSignature,

    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    #[error("Event is not a message")]
    NotMessage,
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
pub struct Message {
    /// The unique identifier of the message
    /// Derived from H(ResidentId + SequenceNumber), where H is a hash function (currently using xxHash).
    pub(crate) id: MessageId,

    /// The source of the message
    pub(crate) source: ResidentId,

    /// The topic to which the message was sent
    pub(crate) topic: Vec<u8>,

    /// The payload of the message
    /// This is the actual data being sent in the message
    pub(crate) payload: Payload,

    /// The signature of the resident
    pub(crate) resident_signature: ResidentSignature,

    /// The signature of the committee
    /// This is optional and is only set when the message need to come from the committee
    pub(crate) committee_signature: Option<CommitteeSignature>,
}

#[derive(Debug)]
#[derive(Default)]
pub struct MessageBuilder {
    id: Option<MessageId>,
    source: Option<ResidentId>,
    topic: Option<Vec<u8>>,
    payload: Option<Payload>,
    resident_signature: Option<ResidentSignature>,
    committee_signature: Option<CommitteeSignature>,
}

impl Message {
    pub fn validate(&self) -> Result<()> {
        if self.payload.need_signature() && self.committee_signature.is_none() {
            return Err(Error::RequireSignature);
        }

        if !self.payload.need_signature() && self.committee_signature.is_some() {
            return Err(Error::NotRequiredSignature);
        }

        Ok(())
    }

    pub fn try_from_gossipsub_event(event: Event) -> Result<Self> {
        Self::try_from(event)
    }

    pub fn to_vec(&self) -> Result<Vec<u8>> {
        self.try_into()
    }
}

impl MessageBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_source(mut self, source: ResidentId, squence_number: u64) -> Self {
        self.source = Some(source);
        self.id = Some(MessageId::new(source, squence_number));
        self
    }

    pub fn set_topic(mut self, topic: Vec<u8>) -> Self {
        self.topic = Some(topic);
        self
    }

    pub fn set_payload(mut self, payload: Payload) -> Self {
        self.payload = Some(payload);
        self
    }

    pub fn set_resident_signature(mut self, signature: ResidentSignature) -> Self {
        self.resident_signature = Some(signature);
        self
    }

    pub fn set_committee_signature(mut self, signature: CommitteeSignature) -> Self {
        self.committee_signature = Some(signature);
        self
    }

    pub fn set_committee_signature_option(mut self, signature: Option<CommitteeSignature>) -> Self {
        self.committee_signature = signature;
        self
    }

    pub fn build(self) -> Result<Message> {
        let id = self.id.ok_or(Error::RequireMessageId)?;
        let source = self.source.ok_or(Error::RequireSource)?;
        let topic = self.topic.ok_or(Error::RequireTopic)?;
        let payload = self.payload.ok_or(Error::RequirePayload)?;
        let resident_signature = self
            .resident_signature
            .ok_or(Error::RequireResidentSignature)?;
        let committee_signature = self.committee_signature;

        let message = Message {
            id,
            source,
            topic,
            payload,
            resident_signature,
            committee_signature,
        };

        message.validate()?;

        Ok(message)
    }
}

impl TryFrom<libp2p::gossipsub::Event> for Message {
    type Error = Error;

    fn try_from(event: Event) -> Result<Self> {
        if let Event::Message { message, .. } = event {
            Self::try_from(&message.data)
        } else {
            Err(Error::NotMessage)
        }
    }
}

impl TryFrom<Message> for Vec<u8> {
    type Error = Error;

    fn try_from(message: Message) -> Result<Self> {
        bincode::serde::encode_to_vec(&message, bincode::config::standard()).map_err(Error::from)
    }
}

impl TryFrom<&Message> for Vec<u8> {
    type Error = Error;

    fn try_from(message: &Message) -> Result<Self> {
        bincode::serde::encode_to_vec(message, bincode::config::standard()).map_err(Error::from)
    }
}

impl TryFrom<&Vec<u8>> for Message {
    type Error = Error;

    fn try_from(value: &Vec<u8>) -> Result<Self> {
        bincode::serde::decode_from_slice(value, bincode::config::standard())
            .map(|(msg, _)| msg)
            .map_err(Error::from)
    }
}

impl TryFrom<&[u8]> for Message {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        bincode::serde::decode_from_slice(value, bincode::config::standard())
            .map(|(msg, _)| msg)
            .map_err(Error::from)
    }
}
