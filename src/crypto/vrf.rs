pub mod config;
pub mod consensus_process;
pub mod crypto;
pub mod messager;
pub mod processes;
pub mod proof;

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use config::Config;
use consensus_process::process::ProcessFactory;
use consensus_process::{ConsensusProcessFactory, ProcessStatus};
use crypto::{CryptoEngine, EcvrfCrypto};
use libp2p::identity;
use libp2p::{gossipsub::MessageId, PeerId};
use messager::{Messager, MessagerEngine};
use processes::Processes;
use thiserror::Error;
use tokio::time::{sleep, sleep_until};

use crate::network::{
    message::{Message, Payload},
    transport::Transport,
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Crypto(#[from] crypto::Error),
    #[error("{0}")]
    Messager(#[from] messager::Error),
    #[error("{0}")]
    Processes(#[from] processes::Error),
    #[error("Timeout waiting for VRF process: {0}")]
    Timeout(MessageId),
    #[error("Process not found: {0}")]
    ProcessNotFound(MessageId),
    #[error("Process failed: {0}")]
    ProcessFailed(MessageId),
    #[error("Failed to verify VRF proof")]
    VerifyVrfProof,
    #[error("PeerId parsing error: {0}")]
    PeerId(#[from] identity::ParseError),
    #[error("Message ID not available")]
    MessageId,
    #[error("Failed to get source peer ID")]
    SourcePeerId,
    #[error("Process error: {0}")]
    Process(String),
}

type Result<T> = std::result::Result<T, Error>;
type ResultCallback = Box<dyn Fn(MessageId, &[u8]) + Send + Sync>;
type FailureCallback = Box<dyn Fn(MessageId) + Send + Sync>;

pub trait VrfEngine: Send + Sync {
    fn new_random(self: Arc<Self>) -> Pin<Box<dyn Future<Output = Result<[u8; 32]>> + Send>>;
    fn set_result_callback(&self, callback: ResultCallback);
    fn set_failure_callback(&self, callback: FailureCallback);
}

pub struct VrfService {
    crypto: EcvrfCrypto,
    messager: Messager,
    processes: Processes,
    peer_id: PeerId,
    config: Config,
    on_result: Mutex<Option<ResultCallback>>,
    on_failure: Mutex<Option<FailureCallback>>,
}

impl VrfService {
    pub async fn new(
        transport: Arc<Transport>,
        config: Config,
        peer_id: PeerId,
        process_factory: Arc<dyn ConsensusProcessFactory>,
    ) -> Result<Arc<Self>> {
        let crypto = EcvrfCrypto::new()?;
        let messager = Messager::new(Arc::clone(&transport), config.topic.clone());
        let processes = Processes::new(
            config.vrf_proof_duration,
            config.vrf_vote_duration,
            process_factory,
        );

        let vrf_service = Arc::new(Self {
            crypto,
            messager,
            processes,
            peer_id,
            config,
            on_result: Mutex::new(None),
            on_failure: Mutex::new(None),
        });

        vrf_service.clone().start_message_handler().await?;
        vrf_service.clone().start_periodic_check().await?;

        Ok(vrf_service)
    }

    async fn start_message_handler(self: Arc<Self>) -> Result<()> {
        let mut rx = self.messager.subscribe().await;

        tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                if let Err(e) = self.handle_message(message).await {
                    eprintln!("Error handling message: {:?}", e);
                }
            }
        });

        Ok(())
    }

    async fn handle_message(&self, message: Message) -> Result<()> {
        if let Message::Gossipsub(msg) = message {
            let source = msg.source.ok_or(Error::SourcePeerId)?;
            match msg.payload {
                Payload::VrfRequest {} => {
                    if let Some(message_id) = msg.message_id {
                        self.handle_vrf_request(message_id).await?;
                    }
                }
                Payload::VrfProof {
                    message_id,
                    public_key,
                    vrf_proof,
                } => {
                    self.handle_vrf_proof(&public_key, vrf_proof.proof(), message_id)
                        .await?;
                }
                Payload::VrfConsensus { message_id, random } => {
                    self.handle_vrf_consensus(source, message_id, &random)?;
                }
                Payload::VrfProcessFailure { message_id } => {
                    self.handle_vrf_failure(message_id, source)?;
                }
                _ => {
                    eprintln!("Unsupported payload type");
                }
            }
        }
        Ok(())
    }

    async fn handle_vrf_request(&self, message_id: MessageId) -> Result<()> {
        let message_id_bytes = message_id_to_bytes(&message_id);
        let proof = self.crypto.generate_proof(&message_id_bytes)?;
        let public_key = self.crypto.public_key().to_vec();

        self.messager
            .send_vrf_proof(message_id.clone(), public_key.clone(), proof.clone())
            .await?;
        self.processes.insert_peer_and_proof(
            message_id.clone(),
            self.peer_id,
            proof.proof().to_vec(),
        )?;

        Ok(())
    }

    async fn handle_vrf_proof(
        &self,
        public_key: &[u8],
        proof: &[u8],
        message_id: MessageId,
    ) -> Result<()> {
        let peer_id = PeerId::from_bytes(public_key).map_err(Error::from)?;
        let message_id_bytes = message_id_to_bytes(&message_id);
        let verify_result = self
            .crypto
            .verify_proof(public_key, proof, &message_id_bytes);

        if verify_result.is_err() {
            eprintln!("Failed to verify VRF proof for message: {:?}", message_id);
            return Err(Error::VerifyVrfProof);
        }

        self.processes
            .insert_peer_and_proof(message_id, peer_id, proof.to_vec())?;
        Ok(())
    }

    fn handle_vrf_failure(&self, message_id: MessageId, source: PeerId) -> Result<()> {
        let should_fail = self.processes.insert_failure_vote(&message_id, source)?;
        if should_fail {
            self.notify_failure(message_id);
        }

        Ok(())
    }

    fn handle_vrf_consensus(
        &self,
        source: PeerId,
        message_id: MessageId,
        random: &[u8; 32],
    ) -> Result<()> {
        let result = self
            .processes
            .insert_completion_vote(&message_id, source, *random)?;

        if let Some(final_random) = result {
            self.notify_result(message_id, &final_random);
        }

        Ok(())
    }

    fn notify_result(&self, message_id: MessageId, random: &[u8]) {
        if let Ok(guard) = self.on_result.lock() {
            if let Some(ref callback) = *guard {
                callback(message_id, random);
            }
        }
    }

    fn notify_failure(&self, message_id: MessageId) {
        if let Ok(guard) = self.on_failure.lock() {
            if let Some(ref callback) = *guard {
                callback(message_id);
            }
        }
    }

    async fn start_periodic_check(self: Arc<Self>) -> Result<()> {
        let self_clone = self.clone();
        tokio::spawn(async move {
            let check_interval = self.config.check_interval;

            loop {
                sleep(check_interval).await;
                self_clone.check_processes().await;
            }
        });

        Ok(())
    }

    async fn check_processes(&self) {
        let failed = self.processes.update_all_status();

        for message_id in failed {
            if let Err(e) = self.send_failure_and_notify(message_id).await {
                eprintln!("Error sending failure message: {:?}", e);
            }
        }
    }

    async fn send_failure_and_notify(&self, message_id: MessageId) -> Result<()> {
        self.messager.send_vrf_failure(message_id.clone()).await?;
        self.notify_failure(message_id);

        Ok(())
    }

    pub async fn new_random(self: Arc<Self>) -> Result<[u8; 32]> {
        let message_id = self.messager.send_vrf_request().await?;
        self.handle_vrf_request(message_id.clone()).await?;

        sleep_until(self.processes.proof_deadline(&message_id)?).await;

        if let Ok(consensus) = self.processes.calculate_consensus(&message_id) {
            self.messager
                .send_vrf_consensus(message_id.clone(), consensus)
                .await?;
        } else {
            self.messager.send_vrf_failure(message_id.clone()).await?;
        }

        sleep_until(self.processes.vote_deadline(&message_id)?).await;

        match self.processes.status(&message_id)? {
            ProcessStatus::Completed(random) => Ok(random),
            ProcessStatus::Failed => Err(Error::ProcessFailed(message_id)),
            ProcessStatus::InProgress => Err(Error::Timeout(message_id)), // Should not happen
        }
    }
}

impl VrfEngine for VrfService {
    fn new_random(self: Arc<Self>) -> Pin<Box<dyn Future<Output = Result<[u8; 32]>> + Send>> {
        Box::pin(self.new_random())
    }

    fn set_result_callback(&self, callback: ResultCallback) {
        if let Ok(mut guard) = self.on_result.lock() {
            *guard = Some(callback);
        }
    }

    fn set_failure_callback(&self, callback: FailureCallback) {
        if let Ok(mut guard) = self.on_failure.lock() {
            *guard = Some(callback);
        }
    }
}

pub struct VrfServiceFactory {
    transport: Arc<Transport>,
    config: Option<Config>,
    process_factory: Option<Arc<dyn ConsensusProcessFactory>>,
    crypto: Option<Arc<dyn CryptoEngine>>,
}

impl VrfServiceFactory {
    const DEFAULT_FACTORY: ProcessFactory = ProcessFactory;

    pub fn new(transport: Arc<Transport>) -> Self {
        Self {
            transport,
            config: None,
            process_factory: None,
            crypto: None,
        }
    }

    pub fn with_config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }

    pub fn with_process_factory(
        mut self,
        process_factory: Arc<dyn ConsensusProcessFactory>,
    ) -> Self {
        self.process_factory = Some(process_factory);
        self
    }

    pub fn with_crypto(mut self, crypto: Arc<dyn CryptoEngine>) -> Self {
        self.crypto = Some(crypto);
        self
    }

    pub async fn create_service(&mut self, peer_id: PeerId) -> Result<Arc<dyn VrfEngine>> {
        let transport = Arc::clone(&self.transport);
        let config = self.get_config();
        let process_factory = self.get_process_factory();
        let vrf_service = VrfService::new(transport, config, peer_id, process_factory).await?;

        Ok(vrf_service as Arc<dyn VrfEngine>)
    }

    fn get_config(&mut self) -> Config {
        if self.config.is_none() {
            self.config = Some(Config::default());
        }
        self.config.clone().unwrap() // Safe to unwrap, and clone is cheap
    }

    fn get_process_factory(&mut self) -> Arc<dyn ConsensusProcessFactory> {
        if self.process_factory.is_none() {
            self.process_factory = Some(Arc::new(Self::DEFAULT_FACTORY));
        }
        self.process_factory.clone().unwrap()
    }
}

fn message_id_to_bytes(message_id: &MessageId) -> Vec<u8> {
    message_id.to_string().as_bytes().to_vec()
}
