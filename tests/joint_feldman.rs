use std::collections::HashMap;

use civita::crypto::{
    dkg::GenerateResult,
    primitives::algebra::{Point, Scalar},
};

use crate::common::joint_feldman;

mod common;

const NUM_PEERS: u16 = 3;
const ID: &[u8] = b"test id";

#[tokio::test]
async fn generate_valid_secret_and_commitment() {
    let mut ctx = joint_feldman::Context::new(NUM_PEERS).await;
    ctx.set_peers().await;
    let results = ctx.generate(ID.to_vec()).await;

    let (secrets, public) = extract_shares_and_public(results);
    let threshold = ctx.threshold();

    assert_eq!(secrets.len(), NUM_PEERS as usize);
    assert!(verify_secret(&secrets, &public, NUM_PEERS)); // full
    assert!(verify_secret(&secrets, &public, threshold)); // equal
    assert!(!verify_secret(&secrets, &public, NUM_PEERS - 1)); // not enough
}

fn extract_shares_and_public(results: HashMap<u16, GenerateResult>) -> (Vec<Scalar>, Point) {
    assert!(
        results
            .values()
            .all(|r| matches!(r, GenerateResult::Success { .. })),
        "All results must be successful"
    );

    let scheme = match results.values().next().unwrap() {
        GenerateResult::Success { secret, .. } => secret.scheme(),
        _ => unreachable!(),
    };

    let mut secrets = vec![Scalar::zero(scheme); results.len()];
    let first_partial_publics = match &results.values().next().unwrap() {
        GenerateResult::Success {
            partial_publics, ..
        } => partial_publics.clone(),
        _ => unreachable!(),
    };

    for (i, result) in results.into_iter() {
        match result {
            GenerateResult::Success {
                secret,
                partial_publics,
            } => {
                assert!(
                    partial_publics == first_partial_publics,
                    "All public keys must be identical"
                );
                secrets[i as usize - 1] = secret;
            }
            _ => unreachable!(),
        }
    }

    let public = Point::sum(first_partial_publics.values().map(|ps| ps.first().unwrap())).unwrap();
    (secrets, public)
}

fn verify_secret(shares: &[Scalar], public: &Point, n: u16) -> bool {
    let indices = (1..=n).collect::<Vec<u16>>();
    let shares = shares
        .iter()
        .take(n as usize)
        .cloned()
        .collect::<Vec<Scalar>>();
    let secret = Scalar::lagrange_interpolation(&indices, &shares).unwrap();
    let expected_public = Point::generator(&secret.scheme()).mul(&secret).unwrap();

    public == &expected_public
}
