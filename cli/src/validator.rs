use civita_core::{
    consensus::validator::Validator as ValidatorTrait,
    crypto::{Hasher, Multihash},
    identity::{PeerId, PublicKey},
    ty::token::Token,
};

use crate::{GENESIS_PEER_PK, INIT_TOKENS};

pub struct Validator;

impl ValidatorTrait for Validator {
    fn genesis() -> (Hasher, u8, Vec<Token>) {
        let pk = GENESIS_PEER_PK
            .get()
            .expect("GENESIS_PEER_PK is not initialized")
            .encode_protobuf();
        let tokens = INIT_TOKENS
            .get()
            .map(|vals| {
                vals.iter()
                    .enumerate()
                    .map(|(i, v)| {
                        Token::new(&Multihash::default(), i as u32, v.to_be_bytes(), pk.clone())
                    })
                    .collect()
            })
            .unwrap_or_default();
        (Hasher::default(), 0, tokens)
    }

    fn validate_script_sig(token_id: Multihash, script_pk: &[u8], script_sig: &[u8]) -> bool {
        let Ok(pk) = PublicKey::try_decode_protobuf(script_pk) else {
            return false;
        };
        pk.verify(&token_id.to_bytes(), script_sig)
    }

    fn validate_conversion(code: u8, inputs: &[Token], created: &[Token]) -> bool {
        if code != 0 {
            return false;
        }

        let total_input = inputs
            .iter()
            .map(|t| u64::from_le_bytes(std::array::from_fn(|i| t.value[i])))
            .sum::<u64>();
        let total_created = created
            .iter()
            .map(|t| u64::from_le_bytes(std::array::from_fn(|i| t.value[i])))
            .sum::<u64>();

        total_input == total_created
    }

    fn is_related(script_pk: &[u8], peer_id: &PeerId) -> bool {
        PublicKey::try_decode_protobuf(script_pk).is_ok_and(|pk| &pk.to_peer_id() == peer_id)
    }

    fn related_peers(script_pk: &[u8]) -> Vec<PeerId> {
        PublicKey::try_decode_protobuf(script_pk).map_or(Vec::new(), |pk| vec![pk.to_peer_id()])
    }
}
