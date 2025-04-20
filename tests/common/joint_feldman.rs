#![allow(dead_code)]

use std::{collections::HashMap, sync::Arc};

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

pub struct PeerInfo {
    pub transport: Arc<Libp2pTransport>,
    pub joint_feldman: JointFeldman<Libp2pTransport>,
    pub pk: PublicKey,
}

pub struct Context {
    peers: IndexedMap<libp2p::PeerId, PeerInfo>,
}

impl PeerInfo {
    pub fn new(
        transport: Arc<Libp2pTransport>,
        joint_feldman: JointFeldman<Libp2pTransport>,
        pk: PublicKey,
    ) -> Self {
        Self {
            transport,
            joint_feldman,
            pk,
        }
    }

    pub async fn set_peers(&mut self, peers: IndexedMap<libp2p::PeerId, PublicKey>) {
        self.joint_feldman
            .set_peers(peers)
            .await
            .expect("Failed to set peers");
    }

    pub async fn generate(&self, id: Vec<u8>) -> dkg::GenerateResult {
        self.joint_feldman
            .generate(id)
            .await
            .expect("Failed to generate")
    }
}

impl Context {
    pub async fn new(n: u16) -> Self {
        let mut peers = IndexedMap::new();

        let transports = transport::create_connected_transports(n).await;
        transports.into_iter().for_each(|transport| {
            let peer_id = transport.self_peer();
            let (sk, pk) = keypair::generate_secp256k1();
            let joint_feldman =
                JointFeldman::new(transport.clone(), sk, joint_feldman::Config::default());
            let peer_info = PeerInfo::new(transport, joint_feldman, pk);
            peers.insert(peer_id, peer_info);
        });

        Self { peers }
    }

    pub async fn set_peers(&mut self) {
        let peers = self.peer_pks();
        for info in self.peers.values_mut() {
            info.set_peers(peers.clone()).await
        }
    }

    fn peer_pks(&self) -> IndexedMap<libp2p::PeerId, PublicKey> {
        self.peers
            .iter()
            .map(|(peer_id, peer_info)| (*peer_id, peer_info.pk.clone()))
            .collect()
    }

    pub async fn generate(&self, id: Vec<u8>) -> HashMap<u16, dkg::GenerateResult> {
        let futures = self
            .peers
            .iter_indexed_values()
            .map(|(i, info)| async {
                let result = info.generate(id.clone()).await;
                (*i, result)
            })
            .collect::<Vec<_>>();

        let results = futures::future::join_all(futures).await;
        results
            .into_iter()
            .collect::<HashMap<u16, dkg::GenerateResult>>()
    }

    pub fn threshold(&self) -> u16 {
        joint_feldman::Config::default()
            .threshold_counter
            .call(self.peers.len())
    }

    pub fn into_iter_peers(self) -> impl Iterator<Item = (libp2p::PeerId, PeerInfo)> {
        self.peers.into_iter()
    }
}
