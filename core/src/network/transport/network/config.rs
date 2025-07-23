use tokio::time::Duration;

const DEFAULT_CHECK_LISTEN_TIMEOUT: Duration = Duration::from_millis(100);
const DEFAULT_CHANNEL_SIZE: usize = 1000;
const DEFAULT_GET_SWARM_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_WAIT_FOR_GOSSIPSUB_PEER_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_WAIT_FOR_GOSSIPSUB_PEER_INTERVAL: Duration = Duration::from_millis(100);
const DEFAULT_WAIT_NEXT_EVENT_TIMEOUT: Duration = Duration::from_millis(10);
const DEFAULT_RECEIVE_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub check_listen_timeout: Duration,
    pub channel_capacity: usize,
    pub get_swarm_lock_timeout: Duration,
    pub wait_for_gossipsub_peer_timeout: Duration,
    pub wait_for_gossipsub_peer_interval: Duration,
    pub wait_next_event_timeout: Duration,
    pub receive_interval: Duration,
}

impl Default for Config {
    fn default() -> Self {
        let check_listen_timeout = DEFAULT_CHECK_LISTEN_TIMEOUT;
        let channel_capacity = DEFAULT_CHANNEL_SIZE;
        let get_swarm_lock_timeout = DEFAULT_GET_SWARM_LOCK_TIMEOUT;
        let wait_for_gossipsub_peer_timeout = DEFAULT_WAIT_FOR_GOSSIPSUB_PEER_TIMEOUT;
        let wait_for_gossipsub_peer_interval = DEFAULT_WAIT_FOR_GOSSIPSUB_PEER_INTERVAL;
        let wait_next_event_timeout = DEFAULT_WAIT_NEXT_EVENT_TIMEOUT;
        let receive_interval = DEFAULT_RECEIVE_INTERVAL;

        Self {
            check_listen_timeout,
            channel_capacity,
            get_swarm_lock_timeout,
            wait_for_gossipsub_peer_timeout,
            wait_for_gossipsub_peer_interval,
            wait_next_event_timeout,
            receive_interval,
        }
    }
}
