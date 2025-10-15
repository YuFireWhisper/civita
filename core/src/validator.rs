use libp2p::PeerId;

use crate::ty::Command;

pub trait ValidatorEngine: Send + Sync + 'static {
    fn validate(cmd: &Command) -> bool;
    fn related_peers(pk: &[u8]) -> Vec<PeerId>;
    fn is_related(pk: &[u8], peer: &PeerId) -> bool {
        Self::related_peers(pk).contains(peer)
    }
}
