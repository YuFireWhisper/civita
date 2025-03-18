use crate::network::transport::libp2p_transport::protocols::{gossipsub, kad, request_response};

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Message {
    Gossipsub(gossipsub::Message),
    RequestResponse(request_response::Message),
    Kad(kad::Message),
}
