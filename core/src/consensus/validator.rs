use libp2p::PeerId;

use crate::ty::{atom::Atom, token::Token};

pub trait Validator: Send + Sync + 'static {
    fn genesis() -> Atom;
    fn validate_script_sig(script_pk: &[u8], script_sig: &[u8]) -> bool;
    fn validate_conversion(code: u8, input: &[Token], created: &[Token]) -> bool;
    fn is_related(script_pk: &[u8], peer_id: &PeerId) -> bool;
    fn related_peers(script_pk: &[u8]) -> Vec<PeerId>;
}
