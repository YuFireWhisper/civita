use civita::crypto::dkg::{classic::Signature, Data, Dkg};
use curv::elliptic::curves::Secp256k1;
use sha2::Sha256;

use crate::common::{
    dkg_classic::generate_classic_nodes, transport::generate_connected_transports,
};

mod common;

type E = Secp256k1;
type H = Sha256;

#[tokio::test]
async fn create_success() {
    const NUM_NODES: u16 = 3;
    let infos = generate_connected_transports(NUM_NODES).await;
    let result = generate_classic_nodes::<E>(infos).await;
    assert!(
        result.is_ok(),
        "failed to create classic nodes: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn valid_sign() {
    const NUM_NODES: u16 = 3;
    const SEED: &[u8] = b"test seed";
    const MESSAGE: &[u8] = b"test message";

    let infos = generate_connected_transports(NUM_NODES).await;
    let nodes = generate_classic_nodes::<E>(infos).await.unwrap();

    let partial_signatures = nodes
        .iter()
        .map(|node| {
            let Data::Classic(data) = node.sign(SEED, MESSAGE);
            data.into()
        })
        .collect::<Vec<Signature<E>>>();

    let indices: Vec<u16> = (0..NUM_NODES).collect();

    let aggregated_signature = Signature::aggregate::<H>(&indices, partial_signatures.into_iter());

    let data = Data::Classic(aggregated_signature.into());

    let is_valid = nodes.iter().all(|node| node.validate(MESSAGE, &data));

    assert!(is_valid, "signature validation failed: {:?}", is_valid);
}
