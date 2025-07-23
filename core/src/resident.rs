// use std::sync::Arc;
//
// use tokio::sync::mpsc;
//
// use crate::{
//     consensus::{self, block::Block, proposal::Proposal},
//     crypto::{Hasher, Multihash},
//     network::{request_response, Transport},
// };
//
// const PROPOSAL_TOPIC: u8 = 0;
// const BLOCK_TOPIC: u8 = 1;
//
// pub struct Config {
//     vdf_param: u16,
//     vdf_difficulty: u64,
// }
//
// pub struct Resident<H: Hasher> {
//     transport: Arc<Transport>,
//     consensus_engine: Arc<consensus::Engine<H>>,
//     pending_validation_proposal_rx: mpsc::UnboundedReceiver<Proposal>,
//     validation_result_tx: mpsc::UnboundedSender<(Multihash, bool)>,
// }
//
// impl<H: Hasher> Resident<H> {
//     // pub fn new(transport: Arc<Transport>, config: Config) -> Self {
//     //     let (pending_validation_proposal_tx, pending_validation_proposal_rx) =
//     //         mpsc::unbounded_channel();
//     //     let (validation_result_tx, validation_result_rx) = mpsc::unbounded_channel();
//     //
//     //     let engine = consensus::engine::EngineBuilder::new()
//     //         .with_transport(transport.clone())
//     //         .with_topics(PROPOSAL_TOPIC, BLOCK_TOPIC);
//     // }
//
//     async fn fetch_current_block() -> Result<Block, request_response::Error> {
//     }
// }
