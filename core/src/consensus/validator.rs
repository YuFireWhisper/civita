use libp2p::PeerId;

use crate::{crypto::Multihash, ty::token::Token};

pub trait Validator {
    fn validate_script_sig(script_pk: &[u8], script_sig: &[u8]) -> bool;
    fn validate_conversion<'a>(
        code: u8,
        input: impl Iterator<Item = &'a Token>,
        consumed: impl Iterator<Item = &'a Multihash>,
        created: &[Token],
    ) -> bool;
    fn is_related(script_pk: &[u8], peer_id: &PeerId) -> bool;
}
