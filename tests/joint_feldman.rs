// use std::collections::HashMap;
//
// use civita::crypto::{
//     algebra::{Point, Scalar},
//     dkg::GenerateResult,
// };
//
// use crate::common::joint_feldman;
//
// mod common;
//
// const NUM_PEERS: u16 = 3;
// const ID: &[u8] = b"test id";
//
// #[tokio::test]
// async fn generate_valid_secret_and_commitment() {
//     let mut ctx = joint_feldman::Context::new(NUM_PEERS).await;
//     ctx.set_peers().await;
//     let results = ctx.generate(ID.to_vec()).await;
//
//     let (secrets, public) = extract_shares_and_public(results);
//     let threshold = ctx.threshold();
//     println!("Threshold: {}", threshold);
//
//     assert_eq!(secrets.len(), NUM_PEERS as usize);
//     assert!(verify_secret(&secrets, &public, NUM_PEERS)); // full
//     assert!(verify_secret(&secrets, &public, threshold)); // equal
//     assert!(!verify_secret(&secrets, &public, threshold - 1)); // not enough
// }
//
// #[tokio::test]
// async fn generate_multiple_times() {
//     const TIMES: usize = 2;
//
//     let mut ctx = joint_feldman::Context::new(NUM_PEERS).await;
//     ctx.set_peers().await;
//
//     for i in 0..TIMES {
//         let mut id = ID.to_vec();
//         id.push(i as u8);
//         let results = ctx.generate(id).await;
//
//         let (secrets, public) = extract_shares_and_public(results);
//         let threshold = ctx.threshold();
//
//         assert_eq!(secrets.len(), NUM_PEERS as usize);
//         assert!(verify_secret(&secrets, &public, NUM_PEERS)); // full
//         assert!(verify_secret(&secrets, &public, threshold)); // equal
//         assert!(!verify_secret(&secrets, &public, threshold - 1)); // not enough
//     }
// }
//
// fn extract_shares_and_public(results: HashMap<u16, GenerateResult>) -> (Vec<Scalar>, Point) {
//     assert!(
//         results
//             .values()
//             .all(|r| matches!(r, GenerateResult::Success { .. })),
//         "All results must be successful"
//     );
//
//     let scheme = match results.values().next().unwrap() {
//         GenerateResult::Success { secret, .. } => secret.scheme(),
//         _ => unreachable!(),
//     };
//
//     let mut secrets = vec![Scalar::zero(scheme); results.len()];
//     let first_public = match &results.values().next().unwrap() {
//         GenerateResult::Success { public, .. } => public.clone(),
//         _ => unreachable!(),
//     };
//
//     for (i, result) in results.into_iter() {
//         match result {
//             GenerateResult::Success { secret, public, .. } => {
//                 assert!(public == first_public, "All public keys must be identical");
//                 secrets[i as usize - 1] = secret;
//             }
//             _ => unreachable!(),
//         }
//     }
//
//     (secrets, first_public)
// }
//
// fn verify_secret(shares: &[Scalar], public: &Point, n: u16) -> bool {
//     let indices = (1..=n).collect::<Vec<u16>>();
//     let shares = shares
//         .iter()
//         .take(n as usize)
//         .cloned()
//         .collect::<Vec<Scalar>>();
//     let secret = Scalar::lagrange_interpolation(&indices, &shares).unwrap();
//     let expected_public = Point::generator(&secret.scheme()).mul(&secret).unwrap();
//
//     public == &expected_public
// }
