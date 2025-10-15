use civita_core::ValidatorEngine;

pub struct Validator;

impl ValidatorEngine for Validator {
    fn validate(_: &civita_core::ty::Command) -> bool {
        true
    }

    fn is_related(pk: &[u8], peer: &libp2p::PeerId) -> bool {
        pk == peer.to_bytes().as_slice()
    }

    fn related_peers(pk: &[u8]) -> Vec<libp2p::PeerId> {
        vec![libp2p::PeerId::from_bytes(pk).unwrap()]
    }
}
