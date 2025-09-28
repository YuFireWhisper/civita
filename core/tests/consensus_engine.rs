use std::sync::Arc;

use civita_core::resident::{Config, Resident};

use crate::common::validator::{token_0, Validator};

mod common;

use common::{constants::*, transport::*};

#[tokio::test]
async fn basic_operations() {
    let dir = tempfile::tempdir().unwrap();
    let str: &'static str = Box::leak(dir.path().to_str().unwrap().to_string().into_boxed_str());

    let config = Config {
        heartbeat_interval: Some(tokio::time::Duration::from_secs(5)),
        block_threshold: 5,
        checkpoint_distance: 10,
        target_block_time: 15,
        max_difficulty_adjustment: 5.0,
        init_vdf_difficulty: 5000,
        vdf_params: VDF_PARAMS,
        storage_dir: str,
    };

    let mut txs = create_transports()
        .await
        .into_iter()
        .map(Arc::new)
        .collect::<Vec<_>>();
    let peers = vec![(txs[0].local_peer_id(), txs[0].listen_addr())];

    assert_eq!(txs[0].local_peer_id(), peer_id_1());

    let mut residents: Vec<Resident<Validator>> = Vec::with_capacity(5);
    residents.push(Resident::genesis(txs.remove(0), config).await.unwrap());

    for tx in txs {
        let t = tokio::time::Duration::from_secs(5);
        let resident = Resident::new(tx, peers.clone(), t, config).await.unwrap();
        residents.push(resident);
    }

    // Pee1 -> Peer 2
    let tokens = residents[0].tokens().await;
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].value, INIT_VALUE.to_be_bytes());

    let inputs = vec![(token_0().id, PEER_ID_1)];
    let created = vec![(INIT_VALUE.to_be_bytes(), PEER_ID_2)];

    residents[0]
        .propose(0, inputs, created)
        .await
        .expect("Failed to propose token transfer");

    tokio::time::timeout(tokio::time::Duration::from_secs(20), async {
        loop {
            if residents[1].tokens().await.len() == 2 {
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    })
    .await
    .expect("Timeout waiting for token transfer");

    let tokens = residents[1].tokens().await;
    assert_eq!(tokens.len(), 2);
    assert_eq!(tokens[0].value, INIT_VALUE.to_be_bytes());
    assert_eq!(tokens[1].value, INIT_VALUE.to_be_bytes());
}
