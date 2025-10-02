use civita_core::{
    resident::{self, Config},
    ty::Token,
};
use libp2p::identity::Keypair;

mod common;

use common::constants::*;

use crate::common::config::ScriptPk;

type Resident = resident::Resident<common::config::Config>;

#[tokio::test]
async fn basic_operations() {
    let dir = tempfile::tempdir().unwrap();
    let str = dir.path().to_str().unwrap();

    let config = Config {
        heartbeat_interval: Some(tokio::time::Duration::from_secs(5)),
        storage_dir: str.to_string(),
        ..Default::default()
    };

    let keypair1 = Keypair::from_protobuf_encoding(&SK_1).unwrap();
    let resident1 = Resident::new(keypair1, config.clone()).await.unwrap();

    let dir2 = tempfile::tempdir().unwrap();
    let str = dir2.path().to_str().unwrap();

    let config = Config {
        bootstrap_peers: vec![(peer_id_1(), resident1.listen_addr().clone())],
        storage_dir: str.to_string(),
        ..config
    };

    let keypair2 = Keypair::from_protobuf_encoding(&SK_2).unwrap();
    let resident2 = Resident::new(keypair2, config.clone()).await.unwrap();

    let dir3 = tempfile::tempdir().unwrap();
    let str = dir3.path().to_str().unwrap();

    let config = Config {
        bootstrap_peers: vec![(peer_id_1(), resident1.listen_addr().clone())],
        storage_dir: str.to_string(),
        ..config
    };

    let keypair3 = Keypair::from_protobuf_encoding(&SK_3).unwrap();
    let _ = Resident::new(keypair3, config.clone()).await.unwrap();

    let dir4 = tempfile::tempdir().unwrap();
    let str = dir4.path().to_str().unwrap();

    let config = Config {
        bootstrap_peers: vec![(peer_id_1(), resident1.listen_addr().clone())],
        storage_dir: str.to_string(),
        ..config
    };

    let keypair4 = Keypair::from_protobuf_encoding(&SK_4).unwrap();
    let _ = Resident::new(keypair4, config.clone()).await.unwrap();

    let dir5 = tempfile::tempdir().unwrap();
    let str = dir5.path().to_str().unwrap();

    let config = Config {
        bootstrap_peers: vec![(peer_id_1(), resident1.listen_addr().clone())],
        storage_dir: str.to_string(),
        ..config
    };

    let keypair5 = Keypair::from_protobuf_encoding(&SK_5).unwrap();
    let _ = Resident::new(keypair5, config.clone()).await.unwrap();

    // Resident1 -> Resident2
    let tokens = resident1.tokens().await.expect("Failed to get tokens");
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens.values().next().unwrap().value, INIT_VALUE);

    let inputs = vec![(*tokens.keys().next().unwrap(), peer_id_1())];
    let created = vec![Token::new(INIT_VALUE, ScriptPk(peer_id_2()))];
    resident1.propose(0, inputs, vec![], created).await.unwrap();

    tokio::time::timeout(tokio::time::Duration::from_secs(20), async {
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
}
