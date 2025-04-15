pub struct Config {
    pub timeout: tokio::time::Duration,
    pub gossipsub_topic: String,
    pub query_channel_size: usize,
}
