use tokio::time::Duration;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_SIGN_TIMEOUT: Duration = Duration::from_secs(5);

pub trait ThresholdCounter: Send + Sync {
    fn call(&self, n: u16) -> u16;
    fn clone_box(&self) -> Box<dyn ThresholdCounter>;
}

impl<F> ThresholdCounter for F
where
    F: Fn(u16) -> u16 + Send + Sync + Clone + 'static,
{
    fn call(&self, n: u16) -> u16 {
        self(n)
    }
    fn clone_box(&self) -> Box<dyn ThresholdCounter> {
        Box::new(self.clone())
    }
}

fn default_threshold_counter(n: u16) -> u16 {
    2 * n / 3 + 1
}

pub struct Config {
    pub timeout: Duration,
    pub sign_timeout: Duration,
    pub threshold_counter: Box<dyn ThresholdCounter>,
}

impl Default for Config {
    fn default() -> Self {
        let timeout = DEFAULT_TIMEOUT;
        let sign_timeout = DEFAULT_SIGN_TIMEOUT;
        let threshold_counter = Box::new(default_threshold_counter);

        Self {
            timeout,
            sign_timeout,
            threshold_counter,
        }
    }
}

impl Clone for Config {
    fn clone(&self) -> Self {
        let timeout = self.timeout;
        let sign_timeout = self.sign_timeout;
        let threshold_counter = self.threshold_counter.clone_box();

        Self {
            timeout,
            sign_timeout,
            threshold_counter,
        }
    }
}
