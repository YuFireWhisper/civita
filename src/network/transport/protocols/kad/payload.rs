use std::time::SystemTime;

use serde::{Deserialize, Serialize};

#[derive(Clone)]
#[derive(Debug)]
#[derive(PartialEq)]
#[derive(Serialize, Deserialize)]
pub enum Payload {
    Resident {
        id: libp2p::PeerId,
        data: Vec<u8>,
        stakes: u32,
        timestamp: SystemTime,
    },

    Proposal(Vec<u8>),

    MerkleDagNode(Vec<u8>),

    Raw(Vec<u8>),
}
