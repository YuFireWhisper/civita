use civita_core::{
    consensus::graph::StorageMode,
    network::transport,
    resident::{self, Config},
};
use futures::future::try_join_all;
use libp2p::{identity::Keypair, Multiaddr};

use crate::common::validator::Validator;

mod common;

#[tokio::test]
async fn basic_operations() {
    const VDF_PARAMS: u16 = 1024;
    const NUM: usize = 5;
    const INIT_VALUE: usize = 100;
    const VALUE: [u8; 8] = INIT_VALUE.to_le_bytes();
    const LISTEN_ADDR: &str = "/ip4/0.0.0.0/tcp/0";

    let config = Config {
        heartbeat_interval: Some(tokio::time::Duration::from_secs(5)),
        block_threshold: 5,
        checkpoint_distance: 10,
        target_block_time: 15,
        max_difficulty_adjustment: 5.0,
        storage_mode: StorageMode::Archive(0),
        init_vdf_difficulty: 5000,
        vdf_params: VDF_PARAMS,
    };

    let listen_addr: Multiaddr = LISTEN_ADDR.parse().unwrap();
    let keypairs: Vec<Keypair> = (0..NUM).map(|_| Keypair::generate_ed25519()).collect();
    let mut residents = Vec::with_capacity(NUM);

    {
        let tx_config = transport::Config::default();
        let iter = (0..NUM).map(|i| (VALUE, keypairs[i].public().to_peer_id().to_bytes()));
        let resident = resident::Builder::default()
            .with_transport_info(keypairs[0].clone(), listen_addr.clone(), tx_config)
            .with_config(config)
            .with_genesis_info(0, iter)
            .build::<Validator>()
            .await
            .expect("Failed to create genesis resident");
        residents.push(resident);
    }

    {
        let tx_config = transport::Config::default();
        let peer_id = keypairs[0].public().to_peer_id();
        let addr = residents[0].listen_addr();
        let peer = vec![(peer_id, addr)];

        let resident_futures = keypairs
            .iter()
            .skip(1)
            .map(|kp| {
                let kp_clone = kp.clone();
                let listen_addr_clone = listen_addr.clone();
                let peer = peer.clone();
                async move {
                    resident::Builder::default()
                        .with_transport_info(kp_clone, listen_addr_clone, tx_config)
                        .with_config(config)
                        .with_normal_info(peer, tokio::time::Duration::from_secs(5))
                        .build::<Validator>()
                        .await
                }
            })
            .collect::<Vec<_>>();

        let normal_residents = try_join_all(resident_futures)
            .await
            .expect("Failed to create normal residents");

        residents.extend(normal_residents);
    }

    // Genesis -> Peer 1
    let tokens = residents[0].tokens().await;
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].value, VALUE);

    let inputs = vec![(tokens[0].id, keypairs[0].public().to_peer_id().to_bytes())];
    let created = vec![(VALUE, keypairs[1].public().to_peer_id().to_bytes())];

    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

    residents[0]
        .propose(0, inputs, created)
        .await
        .expect("Failed to propose token transfer");

    tokio::time::timeout(tokio::time::Duration::from_secs(10), async {
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
    assert_eq!(tokens[0].value, VALUE);
    assert_eq!(tokens[1].value, VALUE);
}
