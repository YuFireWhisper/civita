use tokio::time::Duration;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_SIGN_TIMEOUT: Duration = Duration::from_secs(5);

pub trait ThresholdCounter: Send + Sync {
    fn call(&self, n: u16) -> u16;
    fn clone_box(&self) -> Box<dyn ThresholdCounter>;

    fn default() -> Box<dyn ThresholdCounter>
    where
        Self: Sized,
    {
        Box::new(DefaultThresholdCounter) as Box<dyn ThresholdCounter>
    }
}

#[derive(Clone)]
pub struct DefaultThresholdCounter;

impl ThresholdCounter for DefaultThresholdCounter {
    fn call(&self, n: u16) -> u16 {
        2 * n / 3 + 1
    }

    fn clone_box(&self) -> Box<dyn ThresholdCounter> {
        Box::new(self.clone())
    }
}

pub struct Config {
    pub timeout: Duration,
    pub sign_timeout: Duration,
    pub threshold_counter: Box<dyn ThresholdCounter>,
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

impl Default for Config {
    fn default() -> Self {
        let timeout = DEFAULT_TIMEOUT;
        let sign_timeout = DEFAULT_SIGN_TIMEOUT;
        let threshold_counter = DefaultThresholdCounter::default();

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
