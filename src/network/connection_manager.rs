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
    use std::time::Duration;

    use crate::network::connection_manager::ConnectionManager;

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
}
