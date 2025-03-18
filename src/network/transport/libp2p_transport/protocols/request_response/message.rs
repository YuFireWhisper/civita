use libp2p::{request_response::Event, PeerId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::network::transport::libp2p_transport::protocols::request_response::{
    payload::{Request, Response},
    Payload,
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

impl TryFrom<Event<Request, Response>> for Message {
    type Error = Error;

    fn try_from(event: Event<Request, Response>) -> Result<Self, Self::Error> {
        match event {
            Event::Message { peer, message, .. } => {
                let payload = Payload::from(message);
                Ok(Self { peer, payload })
            }
            _ => Err(Error::NotMessage),
        }
    }
}

#[cfg(test)]
mod mock_message {
    use super::*;

    const PAYLOAD: &[u8] = &[1, 2, 3];

    fn create_request_message() -> Message {
        let peer = PeerId::random();
        let payload = Payload::Request(Request::Raw(PAYLOAD.to_vec()));
        Message { peer, payload }
    }

    fn create_response_message() -> Message {
        let peer = PeerId::random();
        let payload = Payload::Response(Response::Raw(PAYLOAD.to_vec()));
        Message { peer, payload }
    }
}
