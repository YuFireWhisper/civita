use crate::{committee::elector, crypto::threshold};

const DEFAULT_TOPIC: &str = "committee";
const DEFAULT_ELECTION_DURATION: tokio::time::Duration = tokio::time::Duration::from_secs(5);
const DEFAULT_COLLECTION_DURATION: tokio::time::Duration = tokio::time::Duration::from_secs(5);
const DEFAULT_CONSENSUS_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(5);
const DEFAULT_WAITING_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(5);
const DEFAULT_TIME_ERROR: tokio::time::Duration = tokio::time::Duration::from_secs(5);
const DEFAULT_NUM_MEMBERS: u16 = 20;
const DEFAULT_MAX_GENERATION_TIMES: u64 = 10;

#[derive(Clone)]
#[derive(Debug)]
pub struct Config {
    pub topic: String,
    pub election_duration: tokio::time::Duration,
    pub collection_duration: tokio::time::Duration,
    pub consensus_timeout: tokio::time::Duration,
    pub waiting_timeout: tokio::time::Duration,
    pub time_error: tokio::time::Duration,
    pub n_members: u16,
    pub max_generation_times: u64,
    pub threshold_counter: threshold::Counter,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            topic: DEFAULT_TOPIC.to_string(),
            election_duration: DEFAULT_ELECTION_DURATION,
            collection_duration: DEFAULT_COLLECTION_DURATION,
            consensus_timeout: DEFAULT_CONSENSUS_TIMEOUT,
            waiting_timeout: DEFAULT_WAITING_TIMEOUT,
            time_error: DEFAULT_TIME_ERROR,
            n_members: DEFAULT_NUM_MEMBERS,
            max_generation_times: DEFAULT_MAX_GENERATION_TIMES,
            threshold_counter: threshold::Counter::default(),
        }
    }
}

impl From<Config> for elector::Config {
    fn from(value: Config) -> Self {
        Self {
            topic: value.topic,
            election_duration: value.election_duration,
            collection_duration: value.collection_duration,
            consensus_timeout: value.consensus_timeout,
            allowable_time_diff: value.time_error,
            n_members: value.n_members,
            max_times: value.max_generation_times,
            threshold_counter: value.threshold_counter,
        }
    }
}

impl From<&Config> for elector::Config {
    fn from(value: &Config) -> Self {
        Self {
            topic: value.topic.clone(),
            election_duration: value.election_duration,
            collection_duration: value.collection_duration,
            consensus_timeout: value.consensus_timeout,
            allowable_time_diff: value.time_error,
            n_members: value.n_members,
            max_times: value.max_generation_times,
            threshold_counter: value.threshold_counter,
        }
    }
}
