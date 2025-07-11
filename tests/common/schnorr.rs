// #![allow(dead_code)]
//
// use std::{collections::HashMap, sync::Arc};
//
// use civita::{
//     crypto::{
//         algebra::{Point, Scalar},
//         dkg::joint_feldman::JointFeldman,
//         tss::{
//             schnorr::{self, Schnorr},
//             SignResult,
//         },
//     },
//     utils::IndexedMap,
// };
//
// use crate::common::joint_feldman;
//
// pub struct Context {
//     schnorrs: IndexedMap<libp2p::PeerId, Schnorr<JointFeldman>>,
// }
//
// impl Context {
//     pub fn from_joint_feldman_ctx(ctx: joint_feldman::Context) -> Self {
//         let mut schnorrs = IndexedMap::new();
//
//         for (id, info) in ctx.into_iter_peers() {
//             schnorrs.insert(
//                 id,
//                 Schnorr::new(
//                     Arc::new(info.joint_feldman),
//                     info.transport,
//                     schnorr::Config::default(),
//                 ),
//             );
//         }
//
//         Self { schnorrs }
//     }
//
//     pub async fn start(
//         &mut self,
//         secrets: HashMap<u16, Scalar>,
//         public: Point,
//         global_commitments: Vec<Point>,
//     ) {
//         let peers = self
//             .schnorrs
//             .keys()
//             .cloned()
//             .map(|peer_id| (peer_id, ()))
//             .collect::<IndexedMap<libp2p::PeerId, ()>>();
//
//         let results = self
//             .schnorrs
//             .iter_indexed_values_mut()
//             .map(|(index, schnorr)| {
//                 let secret = secrets
//                     .get(&index)
//                     .expect("Secret not found for this peer")
//                     .clone();
//
//                 async {
//                     schnorr
//                         .set_keypair(
//                             secret,
//                             public.clone(),
//                             global_commitments.clone(),
//                             peers.clone(),
//                         )
//                         .await
//                         .expect("Failed to start Schnorr");
//                 }
//             })
//             .collect::<Vec<_>>();
//
//         futures::future::join_all(results).await;
//     }
//
//     pub async fn sign(&self, id: Vec<u8>, msg: &[u8]) -> Vec<SignResult> {
//         let results = self
//             .schnorrs
//             .values()
//             .map(|schnorr| {
//                 let id = id.clone();
//                 let msg = msg.to_vec();
//                 async move { schnorr.sign(id, &msg).await.expect("Failed to sign") }
//             })
//             .collect::<Vec<_>>();
//
//         futures::future::join_all(results).await
//     }
// }
