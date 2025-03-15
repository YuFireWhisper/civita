use libp2p::PeerId;
use serde::{Deserialize, Serialize};

use super::role::Role;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Info {
    pub peer_id: PeerId,
    pub role: Role,
    pub public_key: Vec<u8>,
}
