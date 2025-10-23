use std::fs;

use civita_core::{
    chain_config::ChainConfig,
    consensus::engine::NodeType,
    crypto::Hasher,
    event::Proposal,
    resident::{Config, Resident},
    ty::{Atom, Command},
    utils::mmr::State,
};
use libp2p::identity::Keypair;

mod common;

use common::constants::*;

use crate::common::validator::Validator;

const DIR1: &str = "./data/resident1";
const DIR2: &str = "./data/resident2";
const DIR3: &str = "./data/resident3";
const DIR4: &str = "./data/resident4";
const DIR5: &str = "./data/resident5";

#[tokio::test]
async fn basic_operations() {
    env_logger::builder()
        .is_test(true)
        .filter_module("civita_core", log::LevelFilter::Debug)
        .filter_level(log::LevelFilter::Info)
        .init();

    let _ = fs::remove_dir_all(DIR1);
    let _ = fs::remove_dir_all(DIR2);
    let _ = fs::remove_dir_all(DIR3);
    let _ = fs::remove_dir_all(DIR4);
    let _ = fs::remove_dir_all(DIR5);

    let chain_config = ChainConfig {
        hasher: Hasher::default(),
        vdf_param: 512,
        block_threshold: 2,
        confirmation_depth: 2,
        maintenance_window: 10,
        target_block_time_sec: 1,
        max_vdf_difficulty_adjustment: 1.5,
    };

    let mut config = Config {
        heartbeat_interval: Some(tokio::time::Duration::from_secs(1)),
        storage_dir: DIR1.to_string(),
        ..Default::default()
    };

    let resident1 = {
        let cmd = Command::new(
            0,
            vec![],
            vec![(INIT_VALUE.to_be_bytes(), PEER_ID_1)],
            chain_config.hasher,
        );
        let atom = Atom::new(chain_config)
            .with_command(Some(cmd))
            .with_difficulty(1)
            .solve(chain_config.vdf_param)
            .calculate_state(State::default(), chain_config.hasher);
        println!(
            "Atom ID: {}",
            hex::encode(atom.id(chain_config.hasher).to_bytes())
        );
        let keypair1 = Keypair::from_protobuf_encoding(&SK_1).unwrap();
        Resident::new_genesis::<Validator>(atom, keypair1, config.clone())
            .await
            .unwrap()
    };

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    config.bootstrap_peer = Some((peer_id_1(), resident1.listen_addr().clone()));

    let resident2 = {
        config.storage_dir = DIR2.to_string();
        let keypair2 = Keypair::from_protobuf_encoding(&SK_2).unwrap();
        Resident::new::<Validator>(keypair2, config.clone())
            .await
            .unwrap()
    };

    let _resident3 = {
        config.storage_dir = DIR3.to_string();
        let keypair3 = Keypair::from_protobuf_encoding(&SK_3).unwrap();
        Resident::new::<Validator>(keypair3, config.clone())
            .await
            .unwrap()
    };

    let _resident4 = {
        config.storage_dir = DIR4.to_string();
        let keypair4 = Keypair::from_protobuf_encoding(&SK_4).unwrap();
        Resident::new::<Validator>(keypair4, config.clone())
            .await
            .unwrap()
    };

    let _resident5 = {
        config.storage_dir = DIR5.to_string();
        config.node_type = NodeType::Regular;
        let keypair5 = Keypair::from_protobuf_encoding(&SK_5).unwrap();
        Resident::new::<Validator>(keypair5, config.clone())
            .await
            .unwrap()
    };

    // Resident1 -> Resident2
    let tokens = resident1.tokens().await.expect("Failed to get tokens");
    assert_eq!(tokens.len(), 1);
    assert_eq!(
        tokens.values().next().unwrap().value,
        INIT_VALUE.to_be_bytes()
    );

    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    let inputs = vec![(*tokens.keys().next().unwrap(), PEER_ID_1.to_vec())];
    let created = vec![(INIT_VALUE.to_be_bytes().to_vec(), PEER_ID_2.to_vec())];
    let proposal = Proposal::new(0, inputs, created);
    resident1.propose(proposal).await;

    tokio::time::timeout(tokio::time::Duration::from_secs(60), async {
        loop {
            if resident2.tokens().await.unwrap().len() == 1 {
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    })
    .await
    .expect("Timeout waiting for token transfer");

    let tokens = resident2.tokens().await.expect("Failed to get tokens");
    let tokens = tokens.values().cloned().collect::<Vec<_>>();
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].value, INIT_VALUE.to_be_bytes());

    let _ = fs::remove_dir_all("./data");
}
