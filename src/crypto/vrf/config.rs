use tokio::time::Duration;

pub const DEFAULT_THRESHOLD_PERCENTAGE: f64 = 0.67;
const DEFAULT_VRF_WAIT_DURATION: Duration = Duration::from_millis(5000);
const DEFAULT_CHECK_INTERVAL: Duration = Duration::from_millis(1000);
const DEFAULT_TOPIC: &str = "vrf";
const DEFAULT_MIN_RESPONSES: usize = 3;
const DEFAULT_CANDIDATES_COUNT: usize = 10;

#[derive(Debug, Clone)]
pub struct Config {
    pub topic: String,
    pub vrf_wait_duration: Duration,
    pub check_interval: Duration,
    pub threshold_percentage: f64,
    pub min_responses: usize,
    pub candidates_count: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            topic: DEFAULT_TOPIC.to_string(),
            vrf_wait_duration: DEFAULT_VRF_WAIT_DURATION,
            check_interval: DEFAULT_CHECK_INTERVAL,
            threshold_percentage: DEFAULT_THRESHOLD_PERCENTAGE,
            min_responses: DEFAULT_MIN_RESPONSES,
            candidates_count: DEFAULT_CANDIDATES_COUNT,
        }
    }
}
