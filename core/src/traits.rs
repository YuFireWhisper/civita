use libp2p::PeerId;
use serde::{Deserialize, Serialize};

use crate::{crypto::Hasher, ty::Command};

pub trait ScriptPubKey:
    Clone + Serialize + for<'de> Deserialize<'de> + Send + Sync + 'static
{
    type ScriptSig;

    fn verify(&self, script_sig: &Self::ScriptSig) -> bool;
    fn is_related(&self, peer_id: PeerId) -> bool;
    fn related_peers(&self) -> Vec<PeerId>;
}

pub trait Config: Sized + Send + Sync + 'static {
    type Value: Clone + Serialize + for<'de> Deserialize<'de> + Send + Sync + 'static;
    type ScriptPk: ScriptPubKey<ScriptSig = Self::ScriptSig>;
    type ScriptSig: Clone + Serialize + for<'de> Deserialize<'de> + Send + Sync + 'static;
    type OffChainInput: Clone + Serialize + for<'de> Deserialize<'de> + Send + Sync + 'static;

    const HASHER: Hasher;
    const VDF_PARAM: u16;
    const BLOCK_THRESHOLD: u32;
    const CONFIRMATION_DEPTH: u32;
    const MAINTENANCE_WINDOW: u32;
    const TARGET_BLOCK_TIME_SEC: u64;
    const MAX_VDF_DIFFICULTY_ADJUSTMENT: f64;
    const GENESIS_VAF_DIFFICULTY: u64;

    fn genesis_command() -> Option<Command<Self>>;
    fn validate_command(cmd: &Command<Self>) -> bool;
}
