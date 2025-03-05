pub mod gossipsub;
pub mod request_response;

use libp2p::gossipsub::MessageId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Payload {
    InitRandom {
        threshold: usize,
        total_residents: usize,
    },
    PartialRandom {
        response_for: MessageId,
        share: Vec<u8>,
    },
    RandomValue {
        response_for: MessageId,
        value: Vec<u8>,
        signature: Vec<u8>,
    },
    RawData {
        data: Vec<u8>,
    },
}

#[derive(Debug, Clone)]
pub enum Message {
    Gossipsub(gossipsub::Message),
    RequestResponse(request_response::Message),
}
