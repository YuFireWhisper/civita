use std::sync::Arc;

use civita_core::{
    self,
    consensus::graph::StorageMode,
    resident::{self, Config, Resident},
};

use crate::common::validator::Validator;

mod common;

const VDF_PARAMS: u16 = 1024;

#[tokio::test]
async fn basic_operations() {
    const NUM: usize = 5;
    const INIT_VALUE: usize = 100;

    let config = Config {
        heartbeat_interval: Some(tokio::time::Duration::from_secs(1)),
        block_threshold: 5,
        checkpoint_distance: 10,
        target_block_time: 10,
        max_difficulty_adjustment: 5.0,
        storage_mode: StorageMode::Archive(0),
        init_vdf_difficulty: 1,
        vdf_params: VDF_PARAMS,
    };
    let value = (INIT_VALUE).to_le_bytes();

    let mut txs = common::transport::create_transports(NUM).await;
    let peer_ids = txs.iter().map(|t| t.local_peer_id()).collect::<Vec<_>>();

    let genesis_resident = resident::GenesisBuilder::default()
        .with_command_code(0)
        .with_init_tokens((0..NUM).map(|i| (value, txs[i].local_peer_id().to_bytes())))
        .build::<Validator>(Arc::new(txs.remove(0)), config)
        .await
        .expect("Failed to create genesis resident");

    let mut residents = vec![genesis_resident];

    {
        let ps = vec![peer_ids[0]];
        let t = tokio::time::Duration::from_secs(5);
        for tx in txs.into_iter() {
            let tx = Arc::new(tx);
            let r = Resident::new(tx, ps.clone(), t, config).await.unwrap();
            residents.push(r);
        }
    }

    // Genesis -> Peer 1
    let tokens = residents[0].tokens().await;
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].value, value);

    let inputs = vec![(tokens[0].id, peer_ids[0].to_bytes())];
    let created = vec![(value, peer_ids[1].to_bytes())];

    residents[0]
        .propose(0, inputs, created)
        .await
        .expect("Failed to propose token transfer");

    tokio::time::timeout(tokio::time::Duration::from_secs(10), async {
        loop {
            let tokens = residents[1].tokens().await;
            if tokens.len() == 2 {
                break;
            }
        }
    })
    .await
    .expect("Timeout waiting for token transfer");

    let tokens = residents[1].tokens().await;
    assert_eq!(tokens.len(), 2);
    assert_eq!(tokens[0].value, value);
    assert_eq!(tokens[1].value, value);
}
