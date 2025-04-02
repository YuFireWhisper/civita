use std::sync::Arc;

use civita::crypto::dkg::classic::{config::Config, Classic};
use curv::elliptic::curves::Curve;
use futures::future::join_all;
use libp2p::PeerId;

use crate::common::transport::TransportInfo;

pub async fn generate_classic_nodes<E: Curve>(
    mut infos: Vec<TransportInfo>,
) -> Result<Vec<Classic<E>>, String> {
    infos.sort_by_key(|info| info.peer_id);
    let all_peers: Vec<PeerId> = infos.iter().map(|info| info.peer_id).collect();

    let node_futures = infos.iter().enumerate().map(|(index, info)| {
        let transport = Arc::clone(&info.transport);
        let self_peer = info.peer_id;
        let other_peers = all_peers
            .iter()
            .filter(|&&p| p != self_peer)
            .cloned()
            .collect();

        async move {
            Classic::<E>::new(transport, self_peer, other_peers, Config::default())
                .await
                .map_err(|e| format!("Failed to create node {}: {}", index, e))
        }
    });

    let results = join_all(node_futures).await;
    let nodes: Vec<Classic<E>> = results
        .into_iter()
        .collect::<Result<Vec<Classic<E>>, String>>()?;

    Ok(nodes)
}
