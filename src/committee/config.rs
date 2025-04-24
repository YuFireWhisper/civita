const DEFAULT_TOPIC: &str = "committee";
const BUFFER_TIME: tokio::time::Duration = tokio::time::Duration::from_secs(5);
const EPOCH_DURATION: tokio::time::Duration = tokio::time::Duration::from_secs(60);

#[derive(Clone)]
#[derive(Debug)]
pub struct Config {
    pub topic: String,
    pub buffer_time: tokio::time::Duration,
    pub epoch_duration: tokio::time::Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            topic: DEFAULT_TOPIC.to_string(),
            buffer_time: BUFFER_TIME,
            epoch_duration: EPOCH_DURATION,
        }
    }
}
