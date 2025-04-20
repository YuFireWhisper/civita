#![allow(dead_code)]

use civita::{
    crypto::{
        dkg::{
            self,
            joint_feldman::{self, JointFeldman},
        },
        index_map::IndexedMap,
        keypair::{self, PublicKey},
    },
    network::transport::{Libp2pTransport, Transport},
};

use crate::common::transport;

pub struct Context {
    joint_feldmans: Vec<JointFeldman<Libp2pTransport>>,
    peer_pks: IndexedMap<libp2p::PeerId, PublicKey>,
}

impl Context {
    pub async fn new(n: u16) -> Self {
        let mut joint_feldmans = Vec::new();
        let mut peer_pks: IndexedMap<libp2p::PeerId, PublicKey> = IndexedMap::new();

        let mut transports = transport::create_connected_transports(n).await;
        transports.sort_by_key(|info| info.self_peer());
        transports.into_iter().for_each(|transport| {
            let peer_id = transport.self_peer();
            let (sk, pk) = keypair::generate_secp256k1();
            let joint_feldman = JointFeldman::new(transport, sk, joint_feldman::Config::default());
            joint_feldmans.push(joint_feldman);
            peer_pks.insert(peer_id, pk);
        });

        Self {
            joint_feldmans,
            peer_pks,
        }
    }

    pub async fn set_peers(&mut self) {
        let peers = self.peer_pks.clone();
        for joint_feldman in &mut self.joint_feldmans {
            joint_feldman
                .set_peers(peers.clone())
                .await
                .expect("Failed to set peers");
        }
    }

    pub async fn generate(&self, id: Vec<u8>) -> Vec<dkg::GenerateResult> {
        let results = self.joint_feldmans.iter().map(|joint_feldman| async {
            joint_feldman
                .generate(id.clone())
                .await
                .expect("Failed to generate")
        });

        futures::future::join_all(results).await
    }

    pub fn threshold(&self) -> u16 {
        joint_feldman::Config::default()
            .threshold_counter
            .call(self.joint_feldmans.len() as u16)
    }
}
