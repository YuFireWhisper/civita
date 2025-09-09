use civita_core::{consensus, ty::token::Token};

pub struct Validator;

impl consensus::validator::Validator for Validator {
    fn validate_script_sig(script_pk: &[u8], script_sig: &[u8]) -> bool {
        script_pk == script_sig
    }

    fn validate_conversion(code: u8, inputs: &[Token], created: &[Token]) -> bool {
        if code != 0 {
            return false;
        }

        let total_input = inputs
            .iter()
            .map(|t| usize::from_le_bytes(std::array::from_fn(|i| t.value[i])))
            .sum::<usize>();
        let total_created = created
            .iter()
            .map(|t| usize::from_le_bytes(std::array::from_fn(|i| t.value[i])))
            .sum::<usize>();

        total_input == total_created
    }

    fn is_related(script_pk: &[u8], peer_id: &libp2p::PeerId) -> bool {
        script_pk == peer_id.as_ref().to_bytes()
    }

    fn related_peers(script_pk: &[u8]) -> Vec<libp2p::PeerId> {
        vec![libp2p::PeerId::from_bytes(script_pk).unwrap()]
    }
}
