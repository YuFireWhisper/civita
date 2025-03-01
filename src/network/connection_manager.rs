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

    pub fn on_peer_connected(&mut self, peer_id: &PeerId, endpoint: ConnectedPoint) {
        if let Some(connection) = self.connections.get_mut(peer_id) {
            connection.connected_point = Some(endpoint);
            connection.last_seen = Instant::now();
            connection.status = ConnectionStatus::Connected;
        }
    }

    pub fn on_peer_disconnected(&mut self, peer_id: &PeerId) {
        if let Some(connection) = self.connections.get_mut(peer_id) {
            connection.connected_point = None;
            connection.status = ConnectionStatus::Disconnected;
        }
    }

    pub fn update_last_seen(&mut self, peer_id: &PeerId) {
        if let Some(connection) = self.connections.get_mut(peer_id) {
            connection.last_seen = Instant::now();
        }
    }

    pub fn ban_peer(&mut self, peer_id: PeerId) {
        self.banned_peers.insert(peer_id);
        if let Some(connection) = self.connections.get_mut(&peer_id) {
            connection.status = ConnectionStatus::Banned;
        }
    }

    pub fn unban_peer(&mut self, peer_id: &PeerId) {
        self.banned_peers.remove(peer_id);
        if let Some(connection) = self.connections.get_mut(peer_id) {
            connection.status = ConnectionStatus::Disconnected;
        }
    }

    pub fn is_banned(&self, peer_id: &PeerId) -> bool {
        self.banned_peers.contains(peer_id)
    }

    pub fn get_inactive_peers(&self, timeout: Duration) -> Vec<PeerId> {
        let now = Instant::now();
        self.connections
            .iter()
            .filter(|(_, conn)| {
                conn.status == ConnectionStatus::Connected
                    && now.duration_since(conn.last_seen) > timeout
            })
            .map(|(peer_id, _)| *peer_id)
            .collect()
    }

    pub fn get_bootstrap_peers(&self) -> &[(PeerId, Multiaddr)] {
        &self.bootstrap_peers
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
    use crate::network::connection_manager::{ConnectionManager, ConnectionStatus};
    use libp2p::{
        core::{transport::PortUse, ConnectedPoint, Endpoint},
        Multiaddr, PeerId,
    };
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

    #[test]
    fn test_on_peer_connected() {
        let bootstrap_peers = vec![];
        let connection_timeout = Duration::from_secs(10);
        let mut connection_manager = ConnectionManager::new(bootstrap_peers, connection_timeout);

        let peer_id = PeerId::random();
        let addr: Multiaddr = PEER_ADDR.parse().unwrap();
        let connected_point = ConnectedPoint::Dialer {
            address: addr.clone(),
            role_override: Endpoint::Dialer,
            port_use: PortUse::New,
        };
        connection_manager.add_peer(peer_id, addr.clone());
        connection_manager.on_peer_connected(&peer_id, connected_point.clone());

        assert_eq!(connection_manager.connections.len(), 1);
        assert_eq!(
            connection_manager.connections[&peer_id].connected_point,
            Some(connected_point)
        );
        assert_eq!(
            connection_manager.connections[&peer_id].status,
            ConnectionStatus::Connected
        );
    }

    #[test]
    fn test_on_peer_disconnected() {
        let bootstrap_peers = vec![];
        let connection_timeout = Duration::from_secs(10);
        let mut connection_manager = ConnectionManager::new(bootstrap_peers, connection_timeout);

        let peer_id = PeerId::random();
        let addr: Multiaddr = PEER_ADDR.parse().unwrap();
        let connected_point = ConnectedPoint::Dialer {
            address: addr.clone(),
            role_override: Endpoint::Dialer,
            port_use: PortUse::New,
        };
        connection_manager.add_peer(peer_id, addr.clone());
        connection_manager.on_peer_connected(&peer_id, connected_point.clone());
        connection_manager.on_peer_disconnected(&peer_id);

        assert_eq!(connection_manager.connections.len(), 1);
        assert_eq!(
            connection_manager.connections[&peer_id].connected_point,
            None
        );
        assert_eq!(
            connection_manager.connections[&peer_id].status,
            ConnectionStatus::Disconnected
        );
    }

    #[test]
    fn test_update_last_seen() {
        let bootstrap_peers = vec![];
        let connection_timeout = Duration::from_secs(10);
        let mut connection_manager = ConnectionManager::new(bootstrap_peers, connection_timeout);

        let peer_id = PeerId::random();
        let addr: Multiaddr = PEER_ADDR.parse().unwrap();
        let connected_point = ConnectedPoint::Dialer {
            address: addr.clone(),
            role_override: Endpoint::Dialer,
            port_use: PortUse::New,
        };
        connection_manager.add_peer(peer_id, addr.clone());
        connection_manager.on_peer_connected(&peer_id, connected_point.clone());
        connection_manager.update_last_seen(&peer_id);

        assert_eq!(connection_manager.connections.len(), 1);
        assert!(connection_manager.connections[&peer_id].last_seen.elapsed() < connection_timeout);
    }

    #[test]
    fn test_ban_peer() {
        let bootstrap_peers = vec![];
        let connection_timeout = Duration::from_secs(10);
        let mut connection_manager = ConnectionManager::new(bootstrap_peers, connection_timeout);

        let peer_id = PeerId::random();
        let addr: Multiaddr = PEER_ADDR.parse().unwrap();
        let connected_point = ConnectedPoint::Dialer {
            address: addr.clone(),
            role_override: Endpoint::Dialer,
            port_use: PortUse::New,
        };
        connection_manager.add_peer(peer_id, addr.clone());
        connection_manager.on_peer_connected(&peer_id, connected_point.clone());
        connection_manager.ban_peer(peer_id);

        assert_eq!(connection_manager.connections.len(), 1);
        assert_eq!(connection_manager.banned_peers.len(), 1);
        assert_eq!(
            connection_manager.connections[&peer_id].status,
            ConnectionStatus::Banned
        );
    }

    #[test]
    fn test_unban_peer() {
        let bootstrap_peers = vec![];
        let connection_timeout = Duration::from_secs(10);
        let mut connection_manager = ConnectionManager::new(bootstrap_peers, connection_timeout);

        let peer_id = PeerId::random();
        let addr: Multiaddr = PEER_ADDR.parse().unwrap();
        let connected_point = ConnectedPoint::Dialer {
            address: addr.clone(),
            role_override: Endpoint::Dialer,
            port_use: PortUse::New,
        };
        connection_manager.add_peer(peer_id, addr.clone());
        connection_manager.on_peer_connected(&peer_id, connected_point.clone());
        connection_manager.ban_peer(peer_id);
        connection_manager.unban_peer(&peer_id);

        assert_eq!(connection_manager.connections.len(), 1);
        assert_eq!(connection_manager.banned_peers.len(), 0);
        assert_eq!(
            connection_manager.connections[&peer_id].status,
            ConnectionStatus::Disconnected
        );
    }

    #[test]
    fn test_is_banned() {
        let bootstrap_peers = vec![];
        let connection_timeout = Duration::from_secs(10);
        let mut connection_manager = ConnectionManager::new(bootstrap_peers, connection_timeout);

        let peer_id = PeerId::random();
        let addr: Multiaddr = PEER_ADDR.parse().unwrap();
        let connected_point = ConnectedPoint::Dialer {
            address: addr.clone(),
            role_override: Endpoint::Dialer,
            port_use: PortUse::New,
        };
        connection_manager.add_peer(peer_id, addr.clone());
        connection_manager.on_peer_connected(&peer_id, connected_point.clone());
        connection_manager.ban_peer(peer_id);

        assert!(connection_manager.is_banned(&peer_id));
    }

    #[test]
    fn test_get_inactive_peers() {
        let bootstrap_peers = vec![];
        let connection_timeout = Duration::from_secs(10);
        let mut connection_manager = ConnectionManager::new(bootstrap_peers, connection_timeout);

        let peer_id = PeerId::random();
        let addr: Multiaddr = PEER_ADDR.parse().unwrap();
        let connected_point = ConnectedPoint::Dialer {
            address: addr.clone(),
            role_override: Endpoint::Dialer,
            port_use: PortUse::New,
        };
        connection_manager.add_peer(peer_id, addr.clone());
        connection_manager.on_peer_connected(&peer_id, connected_point.clone());

        let inactive_peers = connection_manager.get_inactive_peers(Duration::from_secs(20));
        assert_eq!(inactive_peers.len(), 0);

        let inactive_peers = connection_manager.get_inactive_peers(Duration::from_secs(5));
        assert_eq!(inactive_peers.len(), 0);

        std::thread::sleep(Duration::from_secs(10));
        let inactive_peers = connection_manager.get_inactive_peers(Duration::from_secs(5));
        assert_eq!(inactive_peers.len(), 1);
        assert_eq!(inactive_peers[0], peer_id);
    }

    #[test]
    fn test_get_bootstrap_peers() {
        let bootstrap_peers = vec![(PeerId::random(), PEER_ADDR.parse().unwrap())];
        let connection_timeout = Duration::from_secs(10);
        let connection_manager =
            ConnectionManager::new(bootstrap_peers.clone(), connection_timeout);

        assert_eq!(connection_manager.get_bootstrap_peers(), &bootstrap_peers);
    }
}
