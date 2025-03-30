use civita::crypto::dkg::Dkg;
use sha2::Sha256;

use crate::common::{
    dkg_classic::generate_classic_nodes, transport::generate_connected_transports,
};

mod common;

type H = Sha256;

#[tokio::test]
async fn create_success() {
    const NUM_NODES: u16 = 3;
    let infos = generate_connected_transports(NUM_NODES).await;
    let result = generate_classic_nodes(infos).await;
    assert!(
        result.is_ok(),
        "failed to create classic nodes: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn valid_sign() {
    const NUM_NODES: u16 = 3;
    const MESSAGE: &[u8] = b"test message";
    let infos = generate_connected_transports(NUM_NODES).await;
    let nodes = generate_classic_nodes(infos).await.unwrap();

    let result = nodes[0].sign(MESSAGE.into()).await;

    assert!(result.is_ok(), "failed to sign: {:?}", result.err());
    assert!(
        result
            .as_ref()
            .unwrap()
            .validate::<H>(MESSAGE, nodes[0].pub_key().unwrap()),
        "failed to validate sign"
    );
}
