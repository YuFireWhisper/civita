use thiserror::Error;

use crate::network::transport::libp2p_transport::{
    behaviour::Event,
    protocols::{gossipsub, kad, request_response},
};

#[macro_export]
macro_rules! extract_variant {
    ($value:expr, $pattern:pat => $result:expr) => {
        match $value {
            $pattern => Some($result),
            _ => None,
        }
    };
    
    (
        $value:expr, 
        $outer_pattern:pat => $inner_expr:expr,
        $inner_pattern:pat => $result:expr
    ) => {
        match $value {
            $outer_pattern => match $inner_expr {
                $inner_pattern => Some($result),
                _ => None,
            },
            _ => None,
        }
    };
    
    (
        $value:expr, 
        $pattern:pat => $result:expr,
        else $else_expr:expr
    ) => {
        match $value {
            $pattern => Some($result),
            _ => $else_expr,
        }
    };
}

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
