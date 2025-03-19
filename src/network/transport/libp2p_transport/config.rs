use tokio::time::Duration;

const DEFAULT_CHECK_LISTEN_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_RECEIVE_INTERVAL: Duration = Duration::from_secs(1);
const DEFAULT_CHANNEL_SIZE: usize = 1000;
const DEFAULT_CLEANUP_CHANNEL_INTERVAL: Duration = Duration::from_secs(60);
const DEFAULT_GET_SWARM_LOCK_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub struct Config {
    pub check_listen_timeout: Duration,
    pub receive_interval: Duration,
    pub channel_capacity: usize,
    pub cleanup_channel_interval: Duration,
    pub get_swarm_lock_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        let check_listen_timeout = DEFAULT_CHECK_LISTEN_TIMEOUT;
        let receive_interval = DEFAULT_RECEIVE_INTERVAL;
        let channel_capacity = DEFAULT_CHANNEL_SIZE;
        let cleanup_channel_interval = DEFAULT_CLEANUP_CHANNEL_INTERVAL;
        let get_swarm_lock_timeout = DEFAULT_GET_SWARM_LOCK_TIMEOUT;

        Self {
            check_listen_timeout,
            receive_interval,
            channel_capacity,
            cleanup_channel_interval,
            get_swarm_lock_timeout,
        }
    }
}
