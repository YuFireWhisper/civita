use std::sync::Arc;

use civita::{
    crypto::dkg::classic::{config::Config, Classic},
    network::transport::libp2p_transport::Libp2pTransport,
};
use curv::elliptic::curves::Secp256k1;
use futures::{future::join_all, TryFutureExt};
use libp2p::PeerId;
use sha2::Sha256;

use crate::common::transport::TransportInfo;

type T = Libp2pTransport;
type E = Secp256k1;
type H = Sha256;

pub async fn generate_classic_nodes(
    infos: Vec<TransportInfo>,
) -> Result<Vec<Classic<T, E>>, String> {
    let all_peers: Vec<PeerId> = infos.iter().map(|info| info.peer_id).collect();

    let node_futures = infos.iter().enumerate().map(|(index, info)| {
        let transport = Arc::clone(&info.transport);
        let self_peer = info.peer_id;
        let other_peers = all_peers
            .iter()
            .filter(|&&p| p != self_peer)
            .cloned()
            .collect();
        Classic::new::<H>(transport, self_peer, other_peers, Config::default())
            .map_err(move |e| format!("Failed to create node at index {}: {:?}", index, e))
    });

    let results = join_all(node_futures).await;

    let nodes: Vec<Classic<T, E>> = results
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;

    Ok(nodes)
}

