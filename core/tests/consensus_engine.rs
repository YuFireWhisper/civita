use std::sync::Arc;

use civita_core::{
    self,
    consensus::{block, engine::Validator, proposal, Engine},
    utils::trie::Record,
};

mod common;

type Hasher = sha2::Sha256;

const VDF_PARAMS: u16 = 1024;
const VDF_DIFFICULTY: u64 = 20;

struct TestValidator {
    valid: bool,
}

impl TestValidator {
    fn new(valid: bool) -> Self {
        Self { valid }
    }
}

impl Validator for TestValidator {
    fn validate_proposal<'a, I>(
        &self,
        _opt_iter: I,
        _proposer_pk: &civita_core::crypto::PublicKey,
        _metadata: Option<&[u8]>,
    ) -> bool
    where
        I: IntoIterator<Item = &'a civita_core::consensus::proposal::Operation>,
    {
        self.valid
    }
}

#[tokio::test]
async fn basic_operations() {
    const NUM: usize = 5;
    const PROPOSAL_TOPIC: u8 = 0;
    const BLOCK_TOPIC: u8 = 1;

    const TARGET_IDX: usize = 4;

    let transports = common::transport::create_transports(NUM).await;

    let target_sk = transports[TARGET_IDX].secret_key().clone();

    let mut engines = Vec::with_capacity(NUM);

    let engine_config = civita_core::consensus::engine::Config {
        proposal_topic: PROPOSAL_TOPIC,
        block_topic: BLOCK_TOPIC,
        vdf_params: VDF_PARAMS,
        vdf_difficulty: VDF_DIFFICULTY,
    };

    for transport in transports.into_iter() {
        let sk = transport.secret_key().clone();

        let engine = Engine::<Hasher, TestValidator>::new(
            Arc::new(transport),
            block::Tree::empty(sk),
            TestValidator::new(true),
            engine_config,
        );

        engine.run().await.expect("Failed to run engine");

        engines.push(engine);
    }

    let key = target_sk.public_key().to_hash::<Hasher>().to_bytes();
    let prop = proposal::Builder::new()
        .with_parent_hash(engines[TARGET_IDX].tip_hash())
        .with_operation(key.clone(), None, Record::new(10, vec![]))
        .with_proposer_pk(target_sk.public_key())
        .build()
        .expect("Failed to build proposal");

    engines[TARGET_IDX]
        .propose(prop)
        .await
        .expect("Failed to propose");

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let is_valid = engines.iter().all(|engine| {
        engine
            .tip_trie()
            .get(&key)
            .is_some_and(|record| record.weight == 10)
    });

    assert!(is_valid, "All engines should have the same record");
}
