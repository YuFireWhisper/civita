use tokio::time::Duration;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_SIGN_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Config {
    pub timeout: Duration,
    pub sign_timeout: Duration,
    pub threshold_counter: Box<dyn Fn(u16) -> u16 + Send + Sync>,
}

impl Default for Config {
    fn default() -> Self {
        let timeout = DEFAULT_TIMEOUT;
        let sign_timeout = DEFAULT_SIGN_TIMEOUT;
        let threshold_counter = Box::new(|n| 2 * n / 3 + 1);

        Self {
            timeout,
            sign_timeout,
            threshold_counter,
        }
    }
}
