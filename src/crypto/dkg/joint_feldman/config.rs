use tokio::time::Duration;

use crate::crypto::primitives::threshold;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_SIGN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
#[derive(Debug)]
pub struct Config {
    pub timeout: Duration,
    pub sign_timeout: Duration,
    pub threshold_counter: threshold::Counter,
}

impl Default for Config {
    fn default() -> Self {
        let timeout = DEFAULT_TIMEOUT;
        let sign_timeout = DEFAULT_SIGN_TIMEOUT;
        let threshold_counter = threshold::Counter::default();

        Self {
            timeout,
            sign_timeout,
            threshold_counter,
        }
    }
}
