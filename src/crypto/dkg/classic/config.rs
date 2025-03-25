use tokio::time::Duration;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Config {
    pub timeout: Duration,
    pub threshold_counter: Box<dyn Fn(u16) -> u16>,
}

impl Default for Config {
    fn default() -> Self {
        let timeout = DEFAULT_TIMEOUT;
        let threshold_counter = Box::new(|n| 2 * n / 3 + 1);
        Config {
            timeout,
            threshold_counter,
        }
    }
}
