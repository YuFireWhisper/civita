use std::{sync::Arc, time::SystemTime};

use multihash_derive::MultihashDigest;

use civita_core::{
    self,
    consensus::graph::StorageMode,
    crypto::{hasher::Hasher, Multihash},
    resident::{Config, Resident},
    ty::{
        atom::{Atom, Command},
        token::Token,
    },
    utils::mmr::Mmr,
};

use crate::common::validator::Validator;

mod common;

const VDF_PARAMS: u16 = 1024;

#[tokio::test]
async fn basic_operations() {
    const NUM: usize = 5;
    const INIT_VALUE: usize = 100;

    let mut transports = common::transport::create_transports(NUM).await;
    let peer_ids = transports
        .iter()
        .map(|t| t.local_peer_id())
        .collect::<Vec<_>>();

    let genesis_atom = {
        let tokens = (0..NUM)
            .map(|i| {
                Token::new(
                    &Multihash::default(),
                    i as u32,
                    INIT_VALUE.to_le_bytes().to_vec(),
                    transports[i].local_peer_id().as_ref().to_bytes(),
                )
            })
            .collect::<Vec<_>>();

        let cmd = Command {
            code: 0,
            inputs: vec![],
            created: tokens,
        };

        let mut atom = Atom {
            hash: Multihash::default(),
            parent: Multihash::default(),
            checkpoint: Multihash::default(),
            height: 0,
            nonce: vec![],
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            cmd: Some(cmd),
            atoms: vec![],
        };

        let hash = Hasher::default().digest(&atom.hash_input());
        atom.hash = hash;

        atom
    };

    let mmr = {
        let mut mmr = Mmr::default();
        for token in genesis_atom.cmd.as_ref().unwrap().created.iter().cloned() {
            mmr.append(token.id, token);
        }
        mmr.commit();
        mmr
    };

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

    let genesis_resident = Resident::<Validator>::with_genesis(
        Arc::new(transports.remove(0)),
        genesis_atom,
        mmr,
        config,
    )
    .await
    .expect("Failed to create genesis resident");

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    let mut residents = vec![genesis_resident];
    for transport in transports.into_iter() {
        let resident = Resident::<Validator>::new(
            Arc::new(transport),
            vec![peer_ids[0]],
            tokio::time::Duration::from_secs(5),
            config,
        )
        .await
        .expect("Failed to create resident");
        residents.push(resident);
    }

    {
        let tokens = residents[0].tokens().await;
        residents[0]
            .propose(
                0,
                tokens
                    .into_iter()
                    .map(|t| (t.id, peer_ids[0].as_ref().to_bytes())),
                std::iter::once((
                    (INIT_VALUE.to_le_bytes()).to_vec(),
                    peer_ids[1].as_ref().to_bytes(),
                )),
            )
            .await
            .expect("Failed to propose initial token");
    }

    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

    let tokens = residents[1].tokens().await;

    assert_eq!(tokens.len(), 2);
}
