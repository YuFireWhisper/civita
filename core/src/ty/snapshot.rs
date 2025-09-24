use serde::{Deserialize, Serialize};

use crate::{crypto::Multihash, ty::atom::Atom};

#[derive(Clone)]
#[derive(Serialize, Deserialize)]
pub struct Snapshot {
    pub atom: Atom,
    pub difficulty: u64,
    pub mmr_size: u64,
    pub peaks: Vec<Multihash>,
}

impl Snapshot {
    pub fn new(atom: Atom, difficulty: u64, mmr_size: u64, peaks: Vec<Multihash>) -> Self {
        Self {
            atom,
            difficulty,
            mmr_size,
            peaks,
        }
    }
}
