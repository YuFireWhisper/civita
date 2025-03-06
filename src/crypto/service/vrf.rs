use std::{collections::HashMap, sync::Arc};

use libp2p::PeerId;
use p256::ecdsa::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::Mutex;
use vrf::{
    openssl::{CipherSuite, ECVRF},
    VRF,
};

use crate::network::{
    message::{gossipsub, Message, Payload},
    transport::{self, SubscriptionFilter, Transport},
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("VRF error: {0}")]
    Vrf(String),
    #[error("{0}")]
    Transport(#[from] transport::Error),
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

impl VrfProof {
    pub fn new(output: Vec<u8>, proof: Vec<u8>) -> Self {
        Self { output, proof }
    }
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

#[derive(Debug, Default)]
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
    vrf: Mutex<ECVRF>,
    private_key: Vec<u8>,
    public_key: Vec<u8>,
    peer_id: PeerId,
    on_vrf_result: Option<OnVrfResult>,
}

impl Vrf {
    pub async fn new(
        transport: Arc<Transport>,
        config: Config,
        peer_id: PeerId,
    ) -> VrfResult<Arc<Self>> {
        let vrf = ECVRF::from_suite(CipherSuite::P256_SHA256_TAI)?;
        let vrf = Mutex::new(vrf);
        let (private_key, public_key) = Self::generate_keypair();
        let state = Arc::new(Mutex::new(State::default()));
        let on_vrf_result = None;

        let vrf = Arc::new(Self {
            transport,
            config,
            state,
            vrf,
            private_key,
            public_key,
            peer_id,
            on_vrf_result,
        });

        vrf.clone().start_message_handler().await?;

        Ok(vrf)
    }

    fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
        let mut rng = OsRng;
        let private_key = SigningKey::random(&mut rng);
        let public_key = VerifyingKey::from(&private_key);
        let private_key = private_key.to_bytes().to_vec();
        let public_key = public_key.to_encoded_point(false).as_bytes().to_vec();

        (private_key, public_key)
    }

    async fn start_message_handler(self: Arc<Self>) -> VrfResult<()> {
        let filter = self.generate_filter();
        let mut rx = self.transport.subscribe(filter).await;

        let self_clone = self.clone();
        tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                if let Err(e) = self_clone.handle_message(message).await {
                    eprintln!("Error handling message: {:?}", e);
                }
            }
        });

        Ok(())
    }

    fn generate_filter(&self) -> SubscriptionFilter {
        SubscriptionFilter::Topic(self.config.topic.clone())
    }

    async fn handle_message(&self, message: Message) -> VrfResult<()> {
        if let Message::Gossipsub(message) = message {
            match message.payload {
                Payload::NewVrfRequest { round } => {
                    self.handle_new_vrf_request(round).await?;
                }
                Payload::NewVrfResponse { round, vrf_proof } => {
                    self.handle_new_vrf_response(round, vrf_proof).await?;
                }
                _ => {
                    eprintln!("Unsupported message payload");
                }
            }
        }
        Ok(())
    }

    async fn handle_new_vrf_request(&self, round: u64) -> VrfResult<()> {
        self.set_round_and_proofs(round).await;
        let vrf_proof = self.get_vrf_proof(round).await?;
        let payload = self.generate_new_vrf_response_payload(round, vrf_proof.clone());
        let message = self.generate_message(payload);
        self.transport.send(message).await?;
        self.set_self_to_round_proofs(round, vrf_proof).await;
        Ok(())
    }

    async fn set_round_and_proofs(&self, round: u64) {
        let mut state_guard = self.state.lock().await;
        state_guard.current_round = round;
        state_guard
            .round_proofs
            .entry(round)
            .or_insert_with(HashMap::new);
    }

    async fn get_vrf_proof(&self, round: u64) -> VrfResult<VrfProof> {
        let input = self.generate_input(round);
        let mut vrf = self.vrf.lock().await;
        let proof = vrf.prove(self.private_key.as_slice(), input.as_slice())?;
        let output = vrf.proof_to_hash(&proof)?;
        Ok(VrfProof::new(output, proof))
    }

    fn generate_input(&self, round: u64) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(round.to_be_bytes());
        hasher.update(self.private_key.as_slice());
        hasher.finalize().to_vec()
    }

    fn generate_new_vrf_response_payload(&self, round: u64, proof: VrfProof) -> Payload {
        Payload::NewVrfResponse {
            round,
            vrf_proof: proof,
        }
    }

    fn generate_message(&self, payload: Payload) -> Message {
        Message::Gossipsub(self.generate_gossipsub_message(payload))
    }

    fn generate_gossipsub_message(&self, payload: Payload) -> gossipsub::Message {
        let topic = self.config.topic.clone();
        gossipsub::Message::new(&topic, payload)
    }

    async fn set_self_to_round_proofs(&self, round: u64, proof: VrfProof) {
        let mut state_guard = self.state.lock().await;
        if let Some(round_proofs) = state_guard.round_proofs.get_mut(&round) {
            round_proofs.insert(self.peer_id, proof);
        }
    }

    async fn handle_new_vrf_response(&self, round: u64, proof: VrfProof) -> VrfResult<()> {
        todo!()
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
