use serde::{Deserialize, Serialize};

use super::message_type::MessageType;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub message_type: MessageType,
    pub source: String,
    pub target: Option<String>,
    pub community_id: Option<String>,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
    pub timestamp: u64,
}
