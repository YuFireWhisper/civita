pub mod gossipsub;
pub mod request_response;

use serde::{Deserialize, Serialize};

use crate::crypto::service::vrf::VrfProof;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Payload {
    NewVrfRequest {
        round: u64,
    },
    NewVrfResponse {
        round: u64,
        vrf_proof: VrfProof,
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
