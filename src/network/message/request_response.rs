use libp2p::{request_response, PeerId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::Payload;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Serde(#[from] serde_json::Error),
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub request_id: Option<String>,
    pub source: PeerId,
    pub target: PeerId,
    pub payload: Payload,
}

impl Message {
    pub fn new(source: PeerId, target: PeerId, payload: Payload) -> Self {
        Self {
            request_id: None,
            source,
            target,
            payload,
        }
    }
}

impl TryFrom<request_response::Message<Message, Message>> for Message {
    type Error = Error;

    fn try_from(message: request_response::Message<Message, Message>) -> Result<Self, Self::Error> {
        match message {
            request_response::Message::Request { request_id, request, .. } => {
                Ok(Message {
                    request_id: Some(request_id.to_string()),
                    source: request.source,
                    target: request.target,
                    payload: request.payload,
                })
            }
            request_response::Message::Response { response, .. } => {
                Ok(response)
            }
        }
    }
}

