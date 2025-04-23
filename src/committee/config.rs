const DEFAULT_TOPIC: &str = "committee";
const BUFFER_TIME: tokio::time::Duration = tokio::time::Duration::from_secs(5);

#[derive(Clone)]
#[derive(Debug)]
pub struct Config {
    pub topic: String,
    pub buffer_time: tokio::time::Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            topic: DEFAULT_TOPIC.to_string(),
            buffer_time: BUFFER_TIME,
        }
    }
}
