pub mod config;
pub mod consensus_process;
pub mod crypto;
pub mod factory;
pub mod messager;
pub mod processes;
pub mod proof;

use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};

use config::Config;
use consensus_process::{ConsensusProcessFactory, ProcessStatus};
use crypto::Crypto;
pub use factory::Factory;
use libp2p::{gossipsub::MessageId, PeerId};
use log::error;
use messager::{Messager, MessagerEngine};
use processes::Processes;
use tokio::time::{sleep, sleep_until};

use crate::network::transport::{
    libp2p_transport::{message::Message, protocols::gossipsub::Payload},
    Transport,
};

use super::{Error, Vrf, VrfCallback};

type Result<T> = std::result::Result<T, Error>;
type ResultCallback = Box<dyn Fn(MessageId, &[u8]) + Send + Sync + 'static>;
type FailureCallback = Box<dyn Fn(MessageId) + Send + Sync + 'static>;

pub struct Components<T: Transport + 'static> {
    pub transport: Arc<T>,
    pub peer_id: PeerId,
    pub config: Config,
    pub process_factory: Arc<dyn ConsensusProcessFactory>,
    pub crypto: Arc<dyn Crypto>,
}

pub struct DVrf<T: Transport + 'static> {
    crypto: Arc<dyn Crypto>, // We use Arc because Crypto may can't be cloned
    messager: Messager<T>,
    processes: Processes,
    peer_id: PeerId,
    config: Config,
    on_result: Mutex<Option<ResultCallback>>,
    on_failure: Mutex<Option<FailureCallback>>,
}

impl<T: Transport> DVrf<T> {
    async fn new_with_components(components: Components<T>) -> Result<Arc<Self>> {
        let crypto = components.crypto;
        let messager = Messager::new(
            Arc::clone(&components.transport),
            components.config.topic.clone(),
        );
        let processes = Processes::new(
            components.config.vrf_proof_duration,
            components.config.vrf_vote_duration,
            components.process_factory,
        );

        let vrf_service = Arc::new(Self {
            crypto,
            messager,
            processes,
            peer_id: components.peer_id,
            config: components.config,
            on_result: Mutex::new(None),
            on_failure: Mutex::new(None),
        });

        vrf_service.clone().start_message_handler().await?;
        vrf_service.clone().start_periodic_check().await?;

        Ok(vrf_service)
    }

    async fn start_message_handler(self: Arc<Self>) -> Result<()> {
        let mut rx = self.messager.subscribe().await?;

        tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                if let Err(e) = self.handle_message(message).await {
                    error!("Error handling message: {:?}", e);
                }
            }
        });

        Ok(())
    }

    async fn handle_message(&self, message: Message) -> Result<()> {
        let Message::Gossipsub(msg) = message else {
            return Err(Error::InvalidMessageType);
        };

        // TODO: Validate sequence number of the message

        match msg.payload {
            Payload::VrfRequest => self.handle_vrf_request(msg.message_id).await,
            Payload::VrfProof {
                message_id: id,
                public_key,
                proof,
            } => self.handle_vrf_proof(&public_key, &proof, id).await,
            Payload::VrfConsensus {
                message_id: id,
                random,
            } => self.handle_vrf_consensus(msg.source, id, &random),
            Payload::VrfProcessFailure(id) => self.handle_vrf_failure(id, msg.source),
            _ => Err(Error::InvalidPayload),
        }
    }

    async fn handle_vrf_request(&self, message_id: MessageId) -> Result<()> {
        let message_id_bytes = message_id_to_bytes(&message_id);
        let proof = self.crypto.generate_proof(&message_id_bytes)?;
        let public_key = self.crypto.public_key().to_vec();

        self.messager
            .send_vrf_proof(message_id.clone(), public_key.clone(), proof.clone())
            .await?;
        self.processes.insert_peer_and_output(
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
        let output = self
            .crypto
            .verify_proof(public_key, proof, &message_id_bytes)?;

        self.processes
            .insert_peer_and_output(message_id, peer_id, output)?;
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

impl<T: Transport> Vrf for DVrf<T> {
    fn new_random(self: Arc<Self>) -> Pin<Box<dyn Future<Output = Result<[u8; 32]>> + Send>> {
        Box::pin(self.new_random())
    }
}

impl<T: Transport> VrfCallback for DVrf<T> {
    fn set_result_callback<F>(&self, callback: F)
    where
        F: Fn(MessageId, &[u8]) + Send + Sync + 'static,
    {
        if let Ok(mut guard) = self.on_result.lock() {
            *guard = Some(Box::new(callback));
        }
    }

    fn set_failure_callback<F>(&self, callback: F)
    where
        F: Fn(MessageId) + Send + Sync + 'static,
    {
        if let Ok(mut guard) = self.on_failure.lock() {
            *guard = Some(Box::new(callback));
        }
    }
}

fn message_id_to_bytes(message_id: &MessageId) -> Vec<u8> {
    message_id.to_string().as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use libp2p::{gossipsub::MessageId, PeerId};
    use tokio::sync::mpsc::channel;
    use tokio::time::Instant;

    use super::config::Config;

    use super::{Components, DVrf};
    use crate::crypto::vrf::dvrf::consensus_process::{
        MockConsensusProcess, MockConsensusProcessFactory, ProcessStatus,
    };
    use crate::crypto::vrf::dvrf::crypto::MockCrypto;
    use crate::crypto::vrf::dvrf::proof::Proof;
    use crate::crypto::vrf::VrfCallback;
    use crate::network::transport::MockTransport;

    const TEST_MESSAGE_ID: &str = "TEST_MESSAGE_ID";
    const TEST_OUTPUT: [u8; 32] = [1; 32];
    const TEST_PFOOF: [u8; 32] = [1; 32];

    fn create_components() -> Components<MockTransport> {
        let mut transport = MockTransport::new();
        transport.expect_listen_on_topic().returning(|_| {
            let (_, rx) = channel(100);
            Ok(rx)
        });

        let mut crypto = MockCrypto::new();
        crypto.expect_public_key().return_const(vec![0u8; 32]);
        crypto
            .expect_generate_proof()
            .returning(|_| Ok(create_proof()));

        let mut process_factory = MockConsensusProcessFactory::new();
        process_factory.expect_create().returning(|_, _| {
            let mut process = MockConsensusProcess::new();
            process.expect_insert_voter().returning(|_| Ok(()));
            process.expect_insert_output().returning(|_| Ok(()));
            process.expect_proof_deadline().returning(Instant::now);
            process.expect_vote_deadline().returning(Instant::now);
            process
                .expect_status()
                .returning(|| ProcessStatus::InProgress);
            Box::new(process)
        });

        let peer_id = PeerId::random();
        let config = Config::default();

        Components {
            transport: Arc::new(transport),
            peer_id,
            config,
            process_factory: Arc::new(process_factory),
            crypto: Arc::new(crypto),
        }
    }

    async fn create_dvrf() -> Arc<DVrf<MockTransport>> {
        let components = create_components();
        DVrf::new_with_components(components).await.unwrap()
    }

    fn create_message_id() -> MessageId {
        MessageId::from(TEST_MESSAGE_ID)
    }

    fn create_proof() -> Proof {
        Proof::new(TEST_OUTPUT.to_vec(), TEST_PFOOF.to_vec())
    }

    #[tokio::test]
    async fn test_new_with_components() {
        let components = create_components();
        let peer_id = components.peer_id;
        let dvrf = super::DVrf::new_with_components(components).await;

        assert!(dvrf.is_ok());
        assert_eq!(dvrf.unwrap().peer_id, peer_id);
    }

    #[tokio::test]
    async fn test_new_random_success() {
        let mut transport = MockTransport::new();
        transport.expect_listen_on_topic().returning(|_| {
            let (_, rx) = channel(100);
            Ok(rx)
        });
        transport.expect_listen_on_peers().returning(|_| {
            let (_, rx) = channel(100);
            Ok(rx)
        });
        transport
            .expect_publish()
            .returning(|_, _| Ok(MessageId::from(TEST_MESSAGE_ID)));

        let mut crypto = MockCrypto::new();
        crypto.expect_public_key().return_const(vec![0u8; 32]);
        crypto
            .expect_generate_proof()
            .returning(|_| Ok(create_proof()))
            .times(1);

        let mut process_factory = MockConsensusProcessFactory::new();
        process_factory
            .expect_create()
            .returning(|_, _| {
                let mut process = MockConsensusProcess::new();
                process.expect_insert_voter().returning(|_| Ok(()));
                process.expect_insert_output().returning(|_| Ok(()));
                process
                    .expect_calculate_consensus()
                    .returning(|| Ok(TEST_OUTPUT));
                process.expect_proof_deadline().returning(Instant::now);
                process.expect_vote_deadline().returning(Instant::now);
                process
                    .expect_status()
                    .returning(|| ProcessStatus::Completed(TEST_OUTPUT));
                Box::new(process)
            })
            .times(1);

        let components = Components {
            transport: Arc::new(transport),
            peer_id: PeerId::random(),
            config: Config::default(),
            process_factory: Arc::new(process_factory),
            crypto: Arc::new(crypto),
        };

        let dvrf = DVrf::new_with_components(components).await.unwrap();
        let result = dvrf.new_random().await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), TEST_OUTPUT);
    }

    #[tokio::test]
    async fn test_set_result_callback() {
        let dvrf = create_dvrf().await;
        let called = Arc::new(Mutex::new(None::<(MessageId, Vec<u8>)>));
        let called_clone = called.clone();

        dvrf.set_result_callback(move |msg_id, random| {
            *called_clone.lock().unwrap() = Some((msg_id, random.to_vec()));
        });

        let message_id = create_message_id();
        dvrf.notify_result(message_id.clone(), &TEST_OUTPUT);

        let result = called.lock().unwrap().take().unwrap();
        assert_eq!(result.0, message_id);
        assert_eq!(result.1, TEST_OUTPUT.to_vec());
    }
}
