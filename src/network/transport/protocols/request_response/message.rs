use libp2p::{request_response::Event, PeerId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::network::transport::{
    dispatcher::Keyed,
    protocols::request_response::{
        payload::{Request, Response},
        Payload,
    },
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("Event is not a message")]
    NotMessage,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct Message {
    pub peer: PeerId,
    pub payload: Payload,
}

impl Message {
    pub fn try_from_request_response_event(event: Event<Request, Response>) -> Result<Self, Error> {
        Self::try_from(event)
    }
}

impl Keyed<PeerId> for Message {
    fn key(&self) -> &PeerId {
        &self.peer
    }
}

impl TryFrom<libp2p::request_response::Event<Request, Response>> for Message {
    type Error = Error;

    fn try_from(
        event: libp2p::request_response::Event<Request, Response>,
    ) -> Result<Self, Self::Error> {
        match event {
            Event::Message { peer, message, .. } => {
                let payload = Payload::from(message);
                Ok(Self { peer, payload })
            }
            _ => Err(Error::NotMessage),
        }
    }
}
