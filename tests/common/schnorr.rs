#![allow(dead_code)]

use std::collections::HashMap;

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
    schnorrs: IndexedMap<libp2p::PeerId, Schnorr<JointFeldman<Libp2pTransport>, Libp2pTransport>>,
}

impl Context {
    pub fn from_joint_feldman_ctx(ctx: joint_feldman::Context) -> Self {
        let mut schnorrs = IndexedMap::new();

        for (id, info) in ctx.into_iter_peers() {
            schnorrs.insert(
                id,
                Schnorr::new(
                    info.joint_feldman,
                    info.transport,
                    schnorr::Config::default(),
                ),
            );
        }

        Self { schnorrs }
    }

    pub async fn start(
        &mut self,
        secrets: HashMap<u16, Scalar>,
        partial_pks: IndexedMap<libp2p::PeerId, Vec<Point>>,
    ) {
        let results = self
            .schnorrs
            .iter_indexed_values_mut()
            .map(|(index, schnorr)| {
                let secret = secrets
                    .get(&index)
                    .expect("Secret not found for this peer")
                    .clone();
                let partial_pks = partial_pks.clone();

                async move {
                    schnorr
                        .start(secret, partial_pks)
                        .await
                        .expect("Failed to start Schnorr");
                }
            })
            .collect::<Vec<_>>();

        futures::future::join_all(results).await;
    }

    pub async fn sign(&self, id: Vec<u8>, msg: &[u8]) -> Vec<SignResult> {
        let results = self
            .schnorrs
            .values()
            .map(|schnorr| {
                let id = id.clone();
                let msg = msg.to_vec();
                async move { schnorr.sign(id, &msg).await.expect("Failed to sign") }
            })
            .collect::<Vec<_>>();

        futures::future::join_all(results).await
    }
}
