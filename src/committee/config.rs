use crate::{committee::elector, constants::DEFAULT_NETWORK_LATENCY, crypto::threshold};

const DEFAULT_TOPIC: &str = "committee";
const DEFAULT_MAX_ATTEMPTS: u8 = 5;
pub const DEFAULT_MAX_COMMITTEE_MEMBERS: u16 = 20;
const DEFAULT_COMMITTEE_TERM: tokio::time::Duration = tokio::time::Duration::from_secs(60);

#[derive(Clone)]
#[derive(Debug)]
pub struct Config {
    pub topic: String,
    pub network_latency: tokio::time::Duration,
    pub committee_term: tokio::time::Duration,
    pub max_members: u16,
    pub max_attempts: u8,
    pub threshold_counter: threshold::Counter,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            topic: DEFAULT_TOPIC.to_string(),
            network_latency: DEFAULT_NETWORK_LATENCY,
            committee_term: DEFAULT_COMMITTEE_TERM,
            max_members: DEFAULT_MAX_COMMITTEE_MEMBERS,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            threshold_counter: threshold::Counter::default(),
        }
    }
}

impl From<Config> for elector::Config {
    fn from(value: Config) -> Self {
        Self {
            topic: value.topic,
            network_latency: value.network_latency,
            committee_term: value.committee_term,
            max_members: value.max_members,
            max_attempts: value.max_attempts,
            threshold_counter: value.threshold_counter,
        }
    }
}

impl From<&Config> for elector::Config {
    fn from(value: &Config) -> Self {
        Self {
            topic: value.topic.clone(),
            network_latency: value.network_latency,
            committee_term: value.committee_term,
            max_members: value.max_members,
            max_attempts: value.max_attempts,
            threshold_counter: value.threshold_counter,
        }
    }
}
