use std::{collections::HashMap, sync::Arc};

use libp2p::PeerId;
use p256::ecdsa::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Mutex;
use vrf::openssl::{CipherSuite, ECVRF};

use crate::network::transport::Transport;

#[derive(Debug, Error)]
pub enum Error {
    #[error("VRF error: {0}")]
    Vrf(String),
}

impl From<vrf::openssl::Error> for Error {
    fn from(err: vrf::openssl::Error) -> Self {
        Self::Vrf(format!("{}", err))
    }
}

type VrfResult<T> = Result<T, Error>;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct VrfProof {
    pub output: Vec<u8>,
    pub proof: Vec<u8>,
}

#[derive(Debug)]
pub struct Config {
    pub topic: String,
    pub timeout_ms: u64,
    pub threshold: f64, // 0.0 - 1.0
}

impl Default for Config {
    fn default() -> Self {
        Self {
            topic: "vrf".to_string(),
            timeout_ms: 1000,
            threshold: 0.67, // 2/3
        }
    }
}

#[derive(Debug)]
struct State {
    current_round: u64,
    peer_public_keys: HashMap<PeerId, Vec<u8>>,
    round_proofs: HashMap<u64, HashMap<PeerId, VrfProof>>,
    completed_rounds: HashMap<u64, Vec<u8>>,
}

type OnVrfResult = Box<dyn Fn(u64, &[u8]) + Send + Sync>;

pub struct Vrf {
    transport: Arc<Transport>,
    config: Config,
    state: Arc<Mutex<State>>,
    vrf: ECVRF,
    private_key: SigningKey,
    public_key: VerifyingKey,
    peer_id: PeerId,
    on_vrf_result: Option<OnVrfResult>,
}

impl Vrf {
    pub async fn new(
        transport: Arc<Transport>,
        config: Config,
        peer_id: PeerId,
    ) -> VrfResult<Self> {
        let vrf = ECVRF::from_suite(CipherSuite::P256_SHA256_TAI)?;
        let mut rng = OsRng;
        let private_key = SigningKey::random(&mut rng);
        let public_key = VerifyingKey::from(&private_key);

        let state = Arc::new(Mutex::new(State {
            current_round: 0,
            peer_public_keys: HashMap::new(),
            round_proofs: HashMap::new(),
            completed_rounds: HashMap::new(),
        }));
        let on_vrf_result = None;

        let vrf = Self {
            transport,
            config,
            state,
            vrf,
            private_key,
            public_key,
            peer_id,
            on_vrf_result,
        };

        Ok(vrf)
    }
}

#[cfg(test)]
mod tests {
    use crate::network::transport::test_transport::TestTransport;

    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_new() {
        let node = TestTransport::new().await.unwrap();
        let transport = Arc::new(node.p2p);
        let peer_id = PeerId::random();
        let config = Config::default();

        let vrf = Vrf::new(transport, config, peer_id).await;

        assert!(vrf.is_ok(), "Vrf should be created");
    }
}
