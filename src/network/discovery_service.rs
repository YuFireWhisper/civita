use std::collections::HashMap;

use libp2p::{
    kad::{self, store::MemoryStore, QueryId},
    Multiaddr, PeerId,
};
use tokio::sync::oneshot;

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

    pub async fn find_peer(
        &mut self,
        kad: &mut kad::Behaviour<MemoryStore>,
        peer_id: PeerId,
    ) -> oneshot::Receiver<Vec<Multiaddr>> {
        let (tx, rx) = tokio::sync::oneshot::channel();

        if let Some(addresses) = self.get_peer_addresses(&peer_id) {
            if !addresses.is_empty() {
                let _ = tx.send(addresses.clone());
                return rx;
            }
        }

        let query_id = kad.get_closest_peers(peer_id);
        self.kad_queries
            .insert(query_id, QueryType::FindPeer(peer_id));

        let senders = self.pending_find_peer_requests.entry(peer_id).or_default();
        senders.push(tx);

        rx
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

    #[tokio::test]
    async fn test_find_peer_when_already_know_peer_id() {
        let mut discovery_service = DiscoveryService::new();
        let peer_id = PeerId::random();
        let addr: Multiaddr = PEER_ADDR.parse().unwrap();

        discovery_service.add_peer_address(peer_id, addr.clone());

        let store = MemoryStore::new(peer_id);
        let mut kad = kad::Behaviour::new(peer_id, store);

        let rx = discovery_service.find_peer(&mut kad, peer_id).await;

        assert_eq!(discovery_service.kad_queries.len(), 0);
        assert_eq!(discovery_service.pending_find_peer_requests.len(), 0);

        let addresses = rx.await.unwrap();
        assert_eq!(addresses.len(), 1);
        assert_eq!(addresses[0], addr);
    }

    #[tokio::test]
    async fn test_find_peer_when_not_know_peer_id() {
        let mut discovery_service = DiscoveryService::new();
        let peer_id = PeerId::random();

        let local_peer_id = PeerId::random();
        let store = MemoryStore::new(local_peer_id);
        let mut kad = kad::Behaviour::new(local_peer_id, store);

        let _rx = discovery_service.find_peer(&mut kad, peer_id).await;

        assert_eq!(discovery_service.kad_queries.len(), 1);

        assert!(discovery_service
            .pending_find_peer_requests
            .contains_key(&peer_id));
        assert_eq!(
            discovery_service
                .pending_find_peer_requests
                .get(&peer_id)
                .unwrap()
                .len(),
            1
        );

        for (_query_id, query_type) in &discovery_service.kad_queries {
            if let QueryType::FindPeer(id) = query_type {
                assert_eq!(*id, peer_id);
            } else {
                panic!("查詢類型不正確");
            }
        }
    }
}
