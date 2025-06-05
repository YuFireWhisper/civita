use std::collections::HashSet;

use libp2p::PeerId;
use tokio::time::Duration;

use crate::{
    consensus::THRESHOLD_MEMBERS, constants::HashArray, crypto::keypair::ResidentSignature,
};

#[derive(Debug)]
pub enum State {
    Prepare,
    PreCommit,
    Commit,
}

#[derive(Debug)]
pub struct View {
    pub number: u64,
    pub leader: PeerId,
    pub timeout: Duration,

    pub proposals: HashSet<Vec<u8>>,
    pub root_hash: HashArray,
    pub parent_ref: HashArray,

    pub qc: [ResidentSignature; THRESHOLD_MEMBERS],
    pub state: State,
    pub height: u64,
}
