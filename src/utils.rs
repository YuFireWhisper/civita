pub mod consensus_collector;
pub mod indexed_map;
pub mod timer;

use std::mem;

pub use indexed_map::IndexedMap;
pub use timer::Timer;

use crate::{constants::HashArray, network::transport::store::merkle_dag::KeyArray};

pub fn hash_to_key(hash: HashArray) -> KeyArray {
    unsafe { mem::transmute::<HashArray, KeyArray>(hash) }
}

pub fn key_to_hash(key: KeyArray) -> HashArray {
    unsafe { mem::transmute::<KeyArray, HashArray>(key) }
}
