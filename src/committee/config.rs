const DEFAULT_TOPIC: &str = "committee";

#[derive(Clone)]
#[derive(Debug)]
pub struct Config {
    pub topic: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            topic: DEFAULT_TOPIC.to_string(),
        }
    }
}
