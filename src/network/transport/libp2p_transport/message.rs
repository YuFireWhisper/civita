use thiserror::Error;

use crate::network::transport::libp2p_transport::{
    behaviour::Event,
    protocols::{gossipsub, kad, request_response},
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Gossipsub(#[from] gossipsub::message::Error),
    #[error("{0}")]
    RequestResponse(#[from] request_response::message::Error),
    #[error("Unsupported message type")]
    UnsupportedMessageType,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Message {
    Gossipsub(gossipsub::Message),
    RequestResponse(request_response::Message),
    Kad(kad::Message),
}

impl TryFrom<Event> for Message {
    type Error = Error;

    fn try_from(event: Event) -> Result<Self, Self::Error> {
        match event {
            Event::Gossipsub(event) => Ok(Self::Gossipsub(gossipsub::Message::try_from(*event)?)),
            Event::RequestResponse(event) => Ok(Self::RequestResponse(
                request_response::Message::try_from(event)?,
            )),
            _ => Err(Error::UnsupportedMessageType),
        }
    }
}
