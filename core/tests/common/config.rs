// use civita_core::{
//     crypto::Hasher,
//     ty::{Command, Token},
// };
// use libp2p::PeerId;
//
// use crate::common::constants::*;
//
// #[derive(Clone, Copy)]
// #[derive(serde::Serialize, serde::Deserialize)]
// pub struct ScriptPk(pub PeerId);
//
// pub struct Config;
//
// impl ScriptPubKey for ScriptPk {
//     type ScriptSig = PeerId;
//
//     fn verify(&self, script_sig: &Self::ScriptSig) -> bool {
//         &self.0 == script_sig
//     }
//
//     fn is_related(&self, peer_id: PeerId) -> bool {
//         self.0 == peer_id
//     }
//
//     fn related_peers(&self) -> Vec<PeerId> {
//         vec![self.0]
//     }
// }
//
// impl traits::Config for Config {
//     type Value = u64;
//     type ScriptPk = ScriptPk;
//     type ScriptSig = PeerId;
//     type OffChainInput = ();
//
//     const HASHER: Hasher = Hasher::Sha2_256;
//     const VDF_PARAM: u16 = 1024;
//     const BLOCK_THRESHOLD: u32 = 3;
//     const CONFIRMATION_DEPTH: u32 = 2;
//     const MAINTENANCE_WINDOW: u32 = 10;
//     const TARGET_BLOCK_TIME_SEC: u64 = 30;
//     const MAX_VDF_DIFFICULTY_ADJUSTMENT: f64 = 1.5;
//     const GENESIS_VAF_DIFFICULTY: u64 = 1;
//
//     fn genesis_command() -> Option<Command<Self>> {
//         let tokens = vec![
//             Token::new(
//                 INIT_VALUE,
//                 ScriptPk(PeerId::from_bytes(&PEER_ID_1).unwrap()),
//             ),
//             Token::new(
//                 INIT_VALUE,
//                 ScriptPk(PeerId::from_bytes(&PEER_ID_2).unwrap()),
//             ),
//             Token::new(
//                 INIT_VALUE,
//                 ScriptPk(PeerId::from_bytes(&PEER_ID_3).unwrap()),
//             ),
//             Token::new(
//                 INIT_VALUE,
//                 ScriptPk(PeerId::from_bytes(&PEER_ID_4).unwrap()),
//             ),
//             Token::new(
//                 INIT_VALUE,
//                 ScriptPk(PeerId::from_bytes(&PEER_ID_5).unwrap()),
//             ),
//         ];
//         let cmd = Command::new(0, vec![], tokens);
//         Some(cmd)
//     }
//
//     fn validate_command(_cmd: &Command<Self>) -> bool {
//         true
//     }
// }
