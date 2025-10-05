use civita_core::{
    crypto::Hasher,
    identity::Keypair,
    traits::{Config, ScriptPubKey},
    ty::Command,
};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SimpleScriptPubKey {
    pub peer_id: PeerId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SimpleScriptSig {
    pub signature: Vec<u8>,
}

impl ScriptPubKey for SimpleScriptPubKey {
    type ScriptSig = SimpleScriptSig;

    fn verify(&self, _script_sig: &Self::ScriptSig) -> bool {
        // Always return true for benchmark purposes
        true
    }

    fn is_related(&self, peer_id: PeerId) -> bool {
        self.peer_id == peer_id
    }

    fn related_peers(&self) -> Vec<PeerId> {
        vec![self.peer_id]
    }
}

impl SimpleScriptPubKey {
    pub fn new(keypair: &Keypair) -> Self {
        Self {
            peer_id: keypair.public().to_peer_id(),
        }
    }
}

pub struct BenchConfig;

impl Config for BenchConfig {
    type Value = u64;
    type ScriptPk = SimpleScriptPubKey;
    type ScriptSig = SimpleScriptSig;
    type OffChainInput = PeerId;

    const HASHER: Hasher = Hasher::Blake3;
    const VDF_PARAM: u16 = 1024;
    const BLOCK_THRESHOLD: u32 = 10;
    const CONFIRMATION_DEPTH: u32 = 3;
    const MAINTENANCE_WINDOW: u32 = 128;
    const TARGET_BLOCK_TIME_SEC: u64 = 50;
    const MAX_VDF_DIFFICULTY_ADJUSTMENT: f64 = 1.2;
    const GENESIS_HEIGHT: u32 = 0;
    const GENESIS_VAF_DIFFICULTY: u64 = 50_0000; // About 30s
    const MAX_BLOCKS_PER_SYNC: u32 = 128;

    fn genesis_command() -> Option<Command<Self>> {
        None
    }

    fn validate_command(_cmd: &Command<Self>) -> bool {
        true
    }
}
