use std::sync::Arc;

use civita_core::{
    self,
    consensus::{
        block::{self, tree::Mode},
        proposal, Engine,
    },
    utils::{Operation, Record},
};
use civita_serialize_derive::Serialize;

mod common;

type Hasher = sha2::Sha256;
type Tree = block::Tree<Hasher, TestRecord>;

const VDF_PARAMS: u16 = 1024;
const VDF_DIFFICULTY: u64 = 1;

#[derive(Clone)]
#[derive(Eq, PartialEq)]
#[derive(Serialize)]
pub struct TestOperation(pub u64);

#[derive(Clone)]
#[derive(Debug)]
#[derive(Default)]
#[derive(Eq, PartialEq)]
#[derive(Serialize)]
pub struct TestRecord(pub u64);

impl Record for TestRecord {
    type Weight = u64;
    type Operation = TestOperation;

    fn try_apply(&mut self, operation: Self::Operation) -> bool {
        self.0 += operation.0;
        true
    }

    fn weight(&self) -> Self::Weight {
        self.0
    }
}

impl Operation for TestOperation {
    fn is_empty(&self) -> bool {
        false
    }

    fn is_order_dependent(&self, _: &[u8]) -> bool {
        false
    }
}

#[tokio::test]
async fn basic_operations() {
    const NUM: usize = 5;
    const PROPOSAL_TOPIC: u8 = 0;
    const BLOCK_TOPIC: u8 = 1;
    const REQUEST_RESPONSE_TOPIC: u8 = 2;

    const TARGET_IDX: usize = 4;

    let transports = common::transport::create_transports(NUM).await;

    let target_sk = transports[TARGET_IDX].secret_key().clone();

    let mut engines = Vec::with_capacity(NUM);

    let engine_config = civita_core::consensus::engine::Config {
        proposal_topic: PROPOSAL_TOPIC,
        block_topic: BLOCK_TOPIC,
        request_response_topic: REQUEST_RESPONSE_TOPIC,
        vdf_params: VDF_PARAMS,
        vdf_difficulty: VDF_DIFFICULTY,
    };

    let tree = Tree::empty(target_sk.clone(), Mode::Archive);
    let blocks = tree.to_blocks().into_iter().collect::<Vec<_>>();

    for transport in transports.into_iter() {
        let sk = transport.secret_key().clone();
        let transport = Arc::new(transport);
        let tree = Tree::from_blocks(sk.clone(), blocks.clone()).expect("Failed to create tree");
        let engine = Engine::new(transport, tree, engine_config);
        let engine = Arc::new(engine);

        tokio::spawn({
            let engine = Arc::clone(&engine);
            async move {
                engine.run().await.expect("Failed to run engine");
            }
        });

        engines.push(engine);
    }

    let key = target_sk.public_key().to_hash::<Hasher>().to_bytes();
    let prop = proposal::Builder::new()
        .with_parent_hash(engines[TARGET_IDX].tip_hash())
        .with_checkpoint(engines[TARGET_IDX].checkpoint_hash())
        .with_operation(key.clone(), TestOperation(10))
        .with_proposer_pk(target_sk.public_key())
        .build()
        .expect("Failed to build proposal");

    let proofs = prop.generate_proofs(&engines[TARGET_IDX].tip_trie());

    engines[TARGET_IDX]
        .propose(prop, proofs)
        .await
        .expect("Failed to propose");

    let is_valid = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        engines.remove(TARGET_IDX);

        loop {
            if engines.iter().any(|engine| {
                engine
                    .tip_trie()
                    .get(&key)
                    .is_some_and(|record| record.weight() == 10)
            }) {
                break true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap_or(false);

    assert!(is_valid, "Proposal was not applied by all engines");
}
