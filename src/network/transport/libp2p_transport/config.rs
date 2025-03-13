use tokio::time::Duration;

const DEFAULT_RECEIVE_INTERVAL: Duration = Duration::from_secs(1);
const DEFAULT_CHANNEL_SIZE: usize = 1000;
const DEFAULT_CLEANUP_CHANNEL_INTERVAL: Duration = Duration::from_secs(60);
const DEFAULT_GET_SWARM_LOCK_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Config {
    pub receive_interval: Duration,
    pub channel_size: usize,
    pub cheanup_channel_interval: Duration,
    pub get_swarm_lock_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        let receive_interval = DEFAULT_RECEIVE_INTERVAL;
        let channel_size = DEFAULT_CHANNEL_SIZE;
        let cheanup_channel_interval = DEFAULT_CLEANUP_CHANNEL_INTERVAL;
        let get_swarm_lock_timeout = DEFAULT_GET_SWARM_LOCK_TIMEOUT;

        Self {
            receive_interval,
            channel_size,
            cheanup_channel_interval,
            get_swarm_lock_timeout,
        }
    }
}
