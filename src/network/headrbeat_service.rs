use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use libp2p::PeerId;

pub struct HeartbeatService {
    last_heartbeat: HashMap<PeerId, Instant>,
    heartbeat_interval: Duration,
    heartbeat_timeout: Duration,
}

impl HeartbeatService {
    pub fn new(heartbeat_interval: Duration, heartbeat_timeout: Duration) -> Self {
        Self {
            last_heartbeat: HashMap::new(),
            heartbeat_interval,
            heartbeat_timeout,
        }
    }

    pub fn update(&mut self, peer_id: PeerId) {
        self.last_heartbeat.insert(peer_id, Instant::now());
    }

    pub fn get_offline_peers(&self) -> Vec<PeerId> {
        let now = Instant::now();
        self.last_heartbeat
            .iter()
            .filter(|(_, last)| now.duration_since(**last) > self.heartbeat_timeout)
            .map(|(peer_id, _)| *peer_id)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::PeerId;

    #[test]
    fn test_new() {
        let heartbeat_interval = Duration::from_secs(1);
        let heartbeat_timeout = Duration::from_secs(2);
        let mut heartbeat_service = HeartbeatService::new(heartbeat_interval, heartbeat_timeout);

        let peer_id = PeerId::random();
        let now = Instant::now();
        heartbeat_service.last_heartbeat.insert(peer_id, now);

        assert_eq!(heartbeat_service.last_heartbeat.get(&peer_id), Some(&now));
    }

    #[test]
    fn test_update() {
        let heartbeat_interval = Duration::from_secs(1);
        let heartbeat_timeout = Duration::from_secs(2);
        let mut heartbeat_service = HeartbeatService::new(heartbeat_interval, heartbeat_timeout);

        let peer_id = PeerId::random();
        heartbeat_service.update(peer_id);

        assert!(heartbeat_service.last_heartbeat.contains_key(&peer_id));
    }

    #[test]
    fn test_get_offline_peers() {
        let heartbeat_interval = Duration::from_secs(1);
        let heartbeat_timeout = Duration::from_secs(2);
        let mut heartbeat_service = HeartbeatService::new(heartbeat_interval, heartbeat_timeout);

        let peer_id1 = PeerId::random();
        let peer_id2 = PeerId::random();
        let now = Instant::now();
        heartbeat_service.last_heartbeat.insert(peer_id1, now);
        heartbeat_service.last_heartbeat.insert(peer_id2, now);

        let offline_peers = heartbeat_service.get_offline_peers();
        assert_eq!(offline_peers.len(), 0);

        std::thread::sleep(heartbeat_timeout);

        let offline_peers = heartbeat_service.get_offline_peers();
        assert_eq!(offline_peers.len(), 2);
        assert!(offline_peers.contains(&peer_id1));
        assert!(offline_peers.contains(&peer_id2));
    }
}
