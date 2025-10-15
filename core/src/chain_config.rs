use serde::{Deserialize, Serialize};

use crate::crypto::Hasher;

#[derive(Clone, Copy)]
#[derive(Debug)]
#[derive(PartialEq)]
#[derive(Serialize, Deserialize)]
pub struct ChainConfig {
    pub hasher: Hasher,
    pub vdf_param: u16,
    pub block_threshold: u32,
    pub confirmation_depth: u32,
    pub maintenance_window: u32,
    pub target_block_time_sec: u64,
    pub max_vdf_difficulty_adjustment: f32,
}
