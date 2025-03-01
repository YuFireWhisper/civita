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
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::PeerId;

    #[test]
    fn test_heartbeat_service() {
        let heartbeat_interval = Duration::from_secs(1);
        let heartbeat_timeout = Duration::from_secs(2);
        let mut heartbeat_service = HeartbeatService::new(heartbeat_interval, heartbeat_timeout);

        let peer_id = PeerId::random();
        let now = Instant::now();
        heartbeat_service.last_heartbeat.insert(peer_id, now);

        assert_eq!(heartbeat_service.last_heartbeat.get(&peer_id), Some(&now));
    }
}
