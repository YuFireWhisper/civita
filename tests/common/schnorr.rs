#![allow(dead_code)]

use civita::{
    crypto::{
        dkg::joint_feldman::JointFeldman,
        index_map::IndexedMap,
        primitives::algebra::{Point, Scalar},
        tss::schnorr::{self, Schnorr, SignResult},
    },
    network::transport::Libp2pTransport,
};

use crate::common::joint_feldman;

pub struct Context {
    schnorrs: Vec<Schnorr<JointFeldman<Libp2pTransport>, Libp2pTransport>>,
}

impl Context {
    pub fn from_joint_feldman_ctx(ctx: joint_feldman::Context) -> Self {
        let schnorrs = ctx
            .into_iter_peers()
            .map(|(_, info)| {
                Schnorr::new(
                    info.joint_feldman,
                    info.transport,
                    schnorr::Config::default(),
                )
            })
            .collect();

        Self { schnorrs }
    }

    pub async fn start(
        &mut self,
        secrets: Vec<Scalar>,
        partial_pks: IndexedMap<libp2p::PeerId, Vec<Point>>,
    ) {
        let results = self
            .schnorrs
            .iter_mut()
            .zip(secrets)
            .map(|(schnorr, secret)| {
                let peer_pks = partial_pks.clone();
                async move { schnorr.start(secret, peer_pks).await }
            })
            .collect::<Vec<_>>();

        futures::future::join_all(results).await;
    }

    pub async fn sign(&self, id: Vec<u8>, msg: &[u8]) -> Vec<SignResult> {
        let results = self
            .schnorrs
            .iter()
            .map(|schnorr| {
                let id = id.clone();
                let msg = msg.to_vec();
                async move { schnorr.sign(id, &msg).await.expect("Failed to sign") }
            })
            .collect::<Vec<_>>();

        futures::future::join_all(results).await
    }
}
