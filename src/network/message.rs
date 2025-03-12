pub mod gossipsub;
pub mod request_response;

use libp2p::gossipsub::MessageId;
use serde::{Deserialize, Serialize};

use crate::crypto::vrf::dvrf::proof::Proof;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Payload {
    VrfRequest {},
    VrfProof {
        message_id: MessageId,
        public_key: Vec<u8>,
        vrf_proof: Proof,
    },
    VrfConsensus {
        message_id: MessageId,
        random: [u8; 32],
    },
    VrfProcessFailure {
        message_id: MessageId,
    },
    RawData {
        data: Vec<u8>,
    },
}

impl Payload {
    pub fn create_vrf_request() -> Payload {
        Payload::VrfRequest {}
    }

    pub fn create_vrf_proof(
        message_id: MessageId,
        public_key: Vec<u8>,
        vrf_proof: Proof,
    ) -> Payload {
        Payload::VrfProof {
            message_id,
            public_key,
            vrf_proof,
        }
    }

    pub fn create_vrf_consensus(message_id: MessageId, random: [u8; 32]) -> Payload {
        Payload::VrfConsensus { message_id, random }
    }

    pub fn create_vrf_failure(message_id: MessageId) -> Payload {
        Payload::VrfProcessFailure { message_id }
    }

    pub fn create_raw_data(data: Vec<u8>) -> Payload {
        Payload::RawData { data }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Message {
    Gossipsub(gossipsub::Message),
    RequestResponse(request_response::Message),
}
