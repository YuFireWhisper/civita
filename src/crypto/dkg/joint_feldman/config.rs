use tokio::time::Duration;

use crate::crypto::primitives::{algebra::Scheme, threshold};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(20);
const DEFAULT_SIGN_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_GOSSIPSUB_TOPIC: &str = "DKG";
const DEFAULT_CHANNEL_SIZE: usize = 100;
const DEFAULT_CRYPTO_SCHEME: Scheme = Scheme::Secp256k1;

#[derive(Clone)]
#[derive(Debug)]
pub struct Config {
    pub timeout: Duration,
    pub sign_timeout: Duration,
    pub threshold_counter: threshold::Counter,
    pub gossipsub_topic: String,
    pub channel_size: usize,
    pub crypto_scheme: Scheme,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            sign_timeout: DEFAULT_SIGN_TIMEOUT,
            threshold_counter: threshold::Counter::default(),
            gossipsub_topic: DEFAULT_GOSSIPSUB_TOPIC.to_string(),
            channel_size: DEFAULT_CHANNEL_SIZE,
            crypto_scheme: DEFAULT_CRYPTO_SCHEME,
        }
    }
}
