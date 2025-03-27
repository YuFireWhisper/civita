use crate::common::{
    dkg_classic::generate_classic_nodes, transport::generate_connected_transports,
};

mod common;

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
