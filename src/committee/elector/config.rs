use crate::{committee::elector::dkg_generator, crypto::threshold};

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

impl From<&Config> for dkg_generator::Config {
    fn from(value: &Config) -> Self {
        Self {
            topic: value.topic.clone(),
            network_latency: value.network_latency,
            committee_term: value.committee_term,
            threshold_counter: value.threshold_counter,
        }
    }
}
