use std::fmt::{Debug, Formatter, Result};

use tokio::time::Duration;

use crate::crypto::dkg::classic::config::{DefaultThresholdCounter, ThresholdCounter};

const DEFAULT_COMMITTEE_CHANGE_BUFFER_TIME: Duration = Duration::from_secs(60);
// Because Duration::from_hours is not const function, we use seconds instead
const ONE_HOUR: u64 = 3600;
const DEFAULT_COMMITTEE_TERM_DURATION: Duration = Duration::from_secs(ONE_HOUR * 2);

pub struct Config {
    pub threshold_counter: Box<dyn ThresholdCounter>,
    pub committee_change_buffer_time: Duration,
    pub committee_term_duration: Duration,
}

impl Config {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_threshold_counter(mut self, threshold_counter: Box<dyn ThresholdCounter>) -> Self {
        self.threshold_counter = threshold_counter;
        self
    }

    pub fn with_committee_change_buffer_time(mut self, time: Duration) -> Self {
        self.committee_change_buffer_time = time;
        self
    }
}

impl Clone for Config {
    fn clone(&self) -> Self {
        let threshold_counter = self.threshold_counter.clone_box();
        let committee_change_buffer_time = self.committee_change_buffer_time;
        let committee_term_duration = self.committee_term_duration;

        Self {
            threshold_counter,
            committee_change_buffer_time,
            committee_term_duration,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        let threshold_counter = DefaultThresholdCounter::default();
        let committee_change_buffer_time = DEFAULT_COMMITTEE_CHANGE_BUFFER_TIME;
        let committee_term_duration = DEFAULT_COMMITTEE_TERM_DURATION;

        Self {
            threshold_counter,
            committee_change_buffer_time,
            committee_term_duration,
        }
    }
}

impl Debug for Config {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("Config")
            .field("threshold_counter", &"Box<dyn ThresholdCounter>")
            .finish()
    }
}
