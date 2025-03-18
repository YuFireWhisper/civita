pub mod request;
pub mod response;

use libp2p::request_response::Message;
pub use request::Request;
pub use response::Response;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Payload {
    Request(Request),
    Response(Response),
}

impl From<Message<Request, Response>> for Payload {
    fn from(message: Message<Request, Response>) -> Self {
        match message {
            Message::Request { request, .. } => Payload::Request(request),
            Message::Response { response, .. } => Payload::Response(response),
        }
    }
}
