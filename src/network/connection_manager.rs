use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

use libp2p::{core::ConnectedPoint, Multiaddr, PeerId};

pub struct ConnectionManager {
    connections: HashMap<PeerId, Connection>,
    bootstrap_peers: Vec<(PeerId, Multiaddr)>,
    banned_peers: HashSet<PeerId>,
    connection_timeout: Duration,
}

impl ConnectionManager {
    pub fn new(bootstrap_peers: Vec<(PeerId, Multiaddr)>, connection_timeout: Duration) -> Self {
        Self {
            connections: HashMap::new(),
            bootstrap_peers,
            banned_peers: HashSet::new(),
            connection_timeout,
        }
    }

    pub fn add_peer(&mut self, peer_id: PeerId, addr: Multiaddr) {
        if self.connections.contains_key(&peer_id) {
            return;
        }

        let connection = self
            .connections
            .entry(peer_id)
            .or_insert_with(|| Connection {
                peer_id,
                addresses: Vec::new(),
                connected_point: None,
                last_seen: Instant::now(),
                status: ConnectionStatus::Disconnected,
            });

        if !connection.addresses.contains(&addr) {
            connection.addresses.push(addr);
        }
    }
}

pub struct Connection {
    peer_id: PeerId,
    addresses: Vec<Multiaddr>,
    connected_point: Option<ConnectedPoint>,
    last_seen: Instant,
    status: ConnectionStatus,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionStatus {
    Connected,
    Disconnected,
    Banned,
}

#[cfg(test)]
mod tests {
    use crate::network::connection_manager::ConnectionManager;
    use libp2p::{Multiaddr, PeerId};
    use std::time::Duration;

    const PEER_ADDR: &str = "/ip4/0.0.0.0/tcp/0";

    #[test]
    fn test_new() {
        let bootstrap_peers = vec![];
        let connection_timeout = Duration::from_secs(10);
        let connection_manager = ConnectionManager::new(bootstrap_peers, connection_timeout);

        assert_eq!(connection_manager.connections.len(), 0);
        assert_eq!(connection_manager.bootstrap_peers.len(), 0);
        assert_eq!(connection_manager.banned_peers.len(), 0);
        assert_eq!(connection_manager.connection_timeout, connection_timeout);
    }

    #[test]
    fn test_add_peer() {
        let bootstrap_peers = vec![];
        let connection_timeout = Duration::from_secs(10);
        let mut connection_manager = ConnectionManager::new(bootstrap_peers, connection_timeout);

        let peer_id = PeerId::random();
        let addr: Multiaddr = PEER_ADDR.parse().unwrap();
        connection_manager.add_peer(peer_id, addr.clone());

        assert_eq!(connection_manager.connections.len(), 1);
        assert_eq!(connection_manager.connections[&peer_id].addresses.len(), 1);
        assert_eq!(connection_manager.connections[&peer_id].addresses[0], addr);
    }
}
