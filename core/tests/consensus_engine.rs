use civita_core::resident::{self, Config};
use libp2p::identity::Keypair;

use crate::common::validator::{token_0, Validator};

mod common;

use common::constants::*;

type Resident = resident::Resident<Validator>;

#[tokio::test]
async fn basic_operations() {
    let dir = tempfile::tempdir().unwrap();
    let str = dir.path().to_str().unwrap();

    let config = Config {
        heartbeat_interval: Some(tokio::time::Duration::from_secs(5)),
        block_threshold: 5,
        checkpoint_distance: 10,
        target_block_time: 15,
        max_difficulty_adjustment: 5.0,
        init_vdf_difficulty: 5000,
        vdf_params: VDF_PARAMS,
        storage_dir: str.to_string(),
        ..Default::default()
    };

    let keypair1 = Keypair::from_protobuf_encoding(&SK_1).unwrap();
    let resident1 = Resident::new(keypair1, config.clone()).await.unwrap();

    let config = Config {
        bootstrap_peers: vec![(peer_id_1(), resident1.listen_addr().clone())],
        ..config
    };

    let keypair2 = Keypair::from_protobuf_encoding(&SK_2).unwrap();
    let resident2 = Resident::new(keypair2, config.clone()).await.unwrap();

    let keypair3 = Keypair::from_protobuf_encoding(&SK_3).unwrap();
    let _ = Resident::new(keypair3, config.clone()).await.unwrap();

    let keypair4 = Keypair::from_protobuf_encoding(&SK_4).unwrap();
    let _ = Resident::new(keypair4, config.clone()).await.unwrap();

    let keypair5 = Keypair::from_protobuf_encoding(&SK_5).unwrap();
    let _ = Resident::new(keypair5, config.clone()).await.unwrap();

    // Resident1 -> Resident2
    let tokens = resident1.tokens().await;
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].value, INIT_VALUE.to_be_bytes());

    let inputs = vec![(token_0().id, PEER_ID_1)];
    let created = vec![(INIT_VALUE.to_be_bytes(), PEER_ID_2)];
    resident1.propose(0, inputs, created).await.unwrap();

    tokio::time::timeout(tokio::time::Duration::from_secs(20), async {
        loop {
            if resident2.tokens().await.len() == 2 {
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    })
    .await
    .expect("Timeout waiting for token transfer");

    let tokens = resident2.tokens().await;
    assert_eq!(tokens.len(), 2);
    assert_eq!(tokens[0].value, INIT_VALUE.to_be_bytes());
    assert_eq!(tokens[1].value, INIT_VALUE.to_be_bytes());
}
