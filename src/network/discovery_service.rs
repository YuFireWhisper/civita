use std::collections::HashMap;

use libp2p::{kad::QueryId, Multiaddr, PeerId};

#[derive(Default)]
pub struct DiscoveryService {
    kad_queries: HashMap<QueryId, QueryType>,
    peer_addresses: HashMap<PeerId, Vec<Multiaddr>>,
    pending_find_peer_requests: HashMap<PeerId, Vec<tokio::sync::oneshot::Sender<Vec<Multiaddr>>>>,
}

enum QueryType {
    FindPeer(PeerId),
    GetProviders(Vec<u8>),
}

impl DiscoveryService {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let discovery_service = DiscoveryService::new();
        assert_eq!(discovery_service.kad_queries.len(), 0);
        assert_eq!(discovery_service.peer_addresses.len(), 0);
        assert_eq!(discovery_service.pending_find_peer_requests.len(), 0);
    }
}
