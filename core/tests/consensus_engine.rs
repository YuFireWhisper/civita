use std::sync::Arc;

use civita_core::{
    self,
    consensus::{
        block,
        proposal::{self, Diff},
    },
    utils::trie::Record,
};
use tokio::sync::mpsc;
use vdf::VDFParams;

mod common;

type Hasher = sha2::Sha256;

const VDF_PARAMS: u16 = 1024;
const VDF_DIFFICULTY: u64 = 20;

#[tokio::test]
async fn basic_operations() {
    const NUM: usize = 5;
    const PROPOSAL_TOPIC: u8 = 0;
    const BLOCK_TOPIC: u8 = 1;
    const THRESHOLD: f64 = 0.67;
    const CODE: u8 = 0;

    let transports = common::transport::create_transports(NUM).await;

    let target_sk = transports[4].secret_key().clone();

    let mut engines = Vec::with_capacity(NUM);

    transports.into_iter().for_each(|transport| {
        let (proposal_tx, mut proposal_rx) = mpsc::unbounded_channel();
        let (validation_tx, validation_rx) = mpsc::unbounded_channel();

        let sk = transport.secret_key().clone();

        let engine = civita_core::consensus::engine::Builder::<Hasher>::new()
            .with_transport(Arc::new(transport))
            .with_topics(PROPOSAL_TOPIC, BLOCK_TOPIC)
            .with_prop_validation_channel(proposal_tx, validation_rx)
            .with_block_tree(block::Tree::with_genesis(sk, THRESHOLD))
            .with_vdf(vdf::WesolowskiVDFParams(VDF_PARAMS).new(), VDF_DIFFICULTY)
            .build();

        tokio::spawn(async move {
            while let Some(proposal) = proposal_rx.recv().await {
                validation_tx
                    .send((proposal.hash::<Hasher>(), true))
                    .expect("Failed to send validation");
            }
        });

        engines.push(engine);
    });

    let key = target_sk.public_key().to_hash::<Hasher>().to_bytes();
    let diff = Diff::new(None, Record::new(10, vec![]));

    let proposal = proposal::Builder::new()
        .with_code(CODE)
        .with_parent(engines[4].tip_hash())
        .with_diff(key, diff)
        .with_proposer_pk(target_sk.public_key())
        .with_proposer_weight(0)
        .build()
        .expect("Failed to build proposal");

    engines[4]
        .propose(proposal)
        .await
        .expect("Failed to propose");

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let record = engines[4].get_self_record();

    assert_eq!(record.weight, 10, "Record weight should be 10");
}
