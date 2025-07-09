// use std::collections::HashMap;
//
// use civita::crypto::{
//     algebra::{Point, Scalar},
//     dkg::GenerateResult,
//     tss::{schnorr::signature::Signature, SignResult},
// };
//
// use crate::common::{joint_feldman, schnorr};
//
// mod common;
//
// const NUM_PEERS: u16 = 3;
// const ID: &[u8] = b"test id";
// const SIG_ID: &[u8] = b"test sig id";
// const MSG: &[u8] = b"test message";
//
// #[tokio::test]
// async fn generate_valid_signature() {
//     let mut ctx = joint_feldman::Context::new(NUM_PEERS).await;
//     ctx.set_peers().await;
//     let results = ctx.generate(ID.to_vec()).await;
//
//     let (secrets, public, global_commitments) = extract_shares_and_public(results);
//
//     let mut schnorr_ctx = schnorr::Context::from_joint_feldman_ctx(ctx);
//     schnorr_ctx
//         .start(secrets, public.clone(), global_commitments)
//         .await;
//
//     let sigs = schnorr_ctx.sign(SIG_ID.to_vec(), MSG).await;
//     let sigs = extract_signature(sigs);
//
//     let first = sigs.first().unwrap();
//     assert!(
//         sigs.iter().all(|sig| sig == first),
//         "All signatures must be identical"
//     );
//     assert!(
//         sigs.iter().all(|sig| sig.verify(MSG, &public)),
//         "Signature verification failed"
//     );
// }
//
// fn extract_shares_and_public(
//     results: HashMap<u16, GenerateResult>,
// ) -> (HashMap<u16, Scalar>, Point, Vec<Point>) {
//     assert!(
//         results
//             .values()
//             .all(|r| matches!(r, GenerateResult::Success { .. })),
//         "All results must be successful"
//     );
//
//     let mut secrets = HashMap::with_capacity(results.len());
//     let first = match &results.values().next().unwrap() {
//         GenerateResult::Success {
//             public,
//             global_commitments,
//             ..
//         } => (public.clone(), global_commitments.clone()),
//         _ => unreachable!(),
//     };
//
//     for (i, result) in results.into_iter() {
//         match result {
//             GenerateResult::Success {
//                 secret,
//                 public,
//                 global_commitments,
//             } => {
//                 assert_eq!(
//                     (public, global_commitments),
//                     first,
//                     "All public keys must be identical",
//                 );
//                 secrets.insert(i, secret.clone());
//             }
//             _ => unreachable!(),
//         }
//     }
//
//     (secrets, first.0, first.1)
// }
//
// fn extract_signature(results: Vec<SignResult>) -> Vec<Signature> {
//     assert!(
//         results
//             .iter()
//             .all(|r| matches!(r, SignResult::Success { .. })),
//         "All results must be successful, invalid peers"
//     );
//
//     results
//         .into_iter()
//         .map(|result| {
//             match result {
//                 SignResult::Success(sig) => sig,
//                 _ => unreachable!(),
//             }
//             .try_into()
//             .unwrap()
//         })
//         .collect()
// }
