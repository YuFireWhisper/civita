use libp2p::PeerId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Info {
    pub chair: Vec<PeerId>,
    pub members: Vec<PeerId>,
    pub public_key: Vec<u8>,
    pub last_change_time: u64,
}
