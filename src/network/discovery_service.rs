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

    pub fn add_peer_address(&mut self, peer_id: PeerId, addr: Multiaddr) {
        let addresses = self.peer_addresses.entry(peer_id).or_default();
        if !addresses.contains(&addr) {
            addresses.push(addr);
        }
    }

    pub fn get_peer_addresses(&self, peer_id: &PeerId) -> Option<&Vec<Multiaddr>> {
        self.peer_addresses.get(peer_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER_ADDR: &str = "/ip4/0.0.0.0/tcp/0";

    #[test]
    fn test_new() {
        let discovery_service = DiscoveryService::new();

        assert_eq!(discovery_service.kad_queries.len(), 0);
        assert_eq!(discovery_service.peer_addresses.len(), 0);
        assert_eq!(discovery_service.pending_find_peer_requests.len(), 0);
    }

    #[test]
    fn test_add_peer_address() {
        let mut discovery_service = DiscoveryService::new();
        let peer_id = PeerId::random();
        let addr: Multiaddr = PEER_ADDR.parse().unwrap();

        discovery_service.add_peer_address(peer_id, addr.clone());

        assert_eq!(discovery_service.peer_addresses.len(), 1);
        assert_eq!(
            discovery_service
                .peer_addresses
                .get(&peer_id)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            discovery_service.peer_addresses.get(&peer_id).unwrap()[0],
            addr
        );
    }

    #[test]
    fn test_get_peer_addresses() {
        let mut discovery_service = DiscoveryService::new();
        let peer_id = PeerId::random();
        let addr: Multiaddr = PEER_ADDR.parse().unwrap();

        discovery_service.add_peer_address(peer_id, addr.clone());

        let addresses = discovery_service.get_peer_addresses(&peer_id).unwrap();

        assert_eq!(addresses.len(), 1);
        assert_eq!(addresses[0], addr);
    }
}
