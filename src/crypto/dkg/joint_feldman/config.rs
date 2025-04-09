use tokio::time::Duration;

use crate::crypto::core::threshold_counter::ThresholdCounter;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_SIGN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
#[derive(Debug)]
pub struct Config {
    pub timeout: Duration,
    pub sign_timeout: Duration,
    pub threshold_counter: ThresholdCounter,
}

impl Default for Config {
    fn default() -> Self {
        let timeout = DEFAULT_TIMEOUT;
        let sign_timeout = DEFAULT_SIGN_TIMEOUT;
        let threshold_counter = ThresholdCounter::default();

        Self {
            timeout,
            sign_timeout,
            threshold_counter,
        }
    }
}
