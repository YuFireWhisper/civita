use std::fs;

use civita_core::{
    consensus::engine::NodeType,
    resident::{self, Config},
    ty::Token,
};
use libp2p::identity::Keypair;

mod common;

use common::constants::*;

use crate::common::config::ScriptPk;

type Resident = resident::Resident<common::config::Config>;

const DIR1: &str = "./data/resident1";
const DIR2: &str = "./data/resident2";
const DIR3: &str = "./data/resident3";
const DIR4: &str = "./data/resident4";
const DIR5: &str = "./data/resident5";

#[tokio::test]
async fn basic_operations() {
    let _ = fs::remove_dir_all(DIR1);
    let _ = fs::remove_dir_all(DIR2);
    let _ = fs::remove_dir_all(DIR3);
    let _ = fs::remove_dir_all(DIR4);
    let _ = fs::remove_dir_all(DIR5);

    let mut config = Config {
        heartbeat_interval: Some(tokio::time::Duration::from_secs(5)),
        storage_dir: DIR1.to_string(),
        ..Default::default()
    };
    let keypair1 = Keypair::from_protobuf_encoding(&SK_1).unwrap();
    let resident1 = Resident::new(keypair1, config.clone()).await.unwrap();

    config.bootstrap_peer = Some((peer_id_1(), resident1.listen_addr().clone()));
    config.storage_dir = DIR2.to_string();

    let keypair2 = Keypair::from_protobuf_encoding(&SK_2).unwrap();
    let resident2 = Resident::new(keypair2, config.clone()).await.unwrap();

    config.storage_dir = DIR3.to_string();

    let keypair3 = Keypair::from_protobuf_encoding(&SK_3).unwrap();
    let _tmp3 = Resident::new(keypair3, config.clone()).await.unwrap();

    config.storage_dir = DIR4.to_string();

    let keypair4 = Keypair::from_protobuf_encoding(&SK_4).unwrap();
    let _tmp4 = Resident::new(keypair4, config.clone()).await.unwrap();

    config.storage_dir = DIR5.to_string();
    config.node_type = NodeType::Regular;

    let keypair5 = Keypair::from_protobuf_encoding(&SK_5).unwrap();
    let _tmp5 = Resident::new(keypair5, config.clone()).await.unwrap();

    // Resident1 -> Resident2
    let tokens = resident1.tokens().await.expect("Failed to get tokens");
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens.values().next().unwrap().value, INIT_VALUE);

    let inputs = vec![(*tokens.keys().next().unwrap(), peer_id_1())];
    let created = vec![Token::new(INIT_VALUE, ScriptPk(peer_id_2()))];
    resident1.propose(0, inputs, vec![], created).await;

    tokio::time::timeout(tokio::time::Duration::from_secs(30), async {
        loop {
            if resident2.tokens().await.unwrap().len() == 2 {
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    })
    .await
    .expect("Timeout waiting for token transfer");

    let tokens = resident2.tokens().await.expect("Failed to get tokens");
    let tokens = tokens.values().cloned().collect::<Vec<_>>();
    assert_eq!(tokens.len(), 2);
    assert_eq!(tokens[0].value, INIT_VALUE);
    assert_eq!(tokens[1].value, INIT_VALUE);

    let _ = fs::remove_dir_all(DIR1);
    let _ = fs::remove_dir_all(DIR2);
    let _ = fs::remove_dir_all(DIR3);
    let _ = fs::remove_dir_all(DIR4);
    let _ = fs::remove_dir_all(DIR5);
}
