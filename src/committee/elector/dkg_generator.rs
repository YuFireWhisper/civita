use std::{collections::HashSet, sync::Arc, time::SystemTime};

use crate::{
    committee,
    crypto::{
        algebra::{Point, Scalar},
        dkg::{self, Dkg},
        keypair::PublicKey,
        threshold,
    },
    network::transport::{self, protocols::gossipsub},
    utils::{
        consensus_collector::{self, ConsensusCollector},
        IndexedMap,
    },
};

#[cfg(not(test))]
use crate::network::transport::Transport;

#[cfg(test)]
use crate::network::transport::MockTransport as Transport;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Transport(#[from] transport::Error),

    #[error("{0}")]
    Dkg(String),

    #[error("Consensus time failed")]
    ConsensusTimeFailed,

    #[error("Peer not found")]
    PeerNotFound,

    #[error("Channel closed")]
    ChannelClosed,

    #[error("{0}")]
    Collector(#[from] consensus_collector::Error),

    #[error("Self peer not found in candidates")]
    SelfPeerNotInCandidates,
}

pub enum GenerateResult {
    Success {
        info: Box<committee::Info>,
        secret: Scalar,
        global_commitments: Vec<Point>,
    },
    Failure(HashSet<libp2p::PeerId>),
}

#[derive(Clone)]
#[derive(Debug)]
pub struct Config {
    pub topic: String,
    pub network_latency: tokio::time::Duration,
    pub committee_term: tokio::time::Duration,
    pub threshold_counter: threshold::Counter,
}

pub struct Validator {
    transport: Arc<Transport>,
    proposal_peer: libp2p::PeerId,
    now: SystemTime,
    topic: String,
    conmmittee_term: tokio::time::Duration,
}

pub struct DkgGenerator<D: Dkg> {
    transport: Arc<Transport>,
    dkg: Arc<D>,
    config: Config,
}

impl Validator {
    fn validate_time(&self, end_time: SystemTime) -> bool {
        if let Ok(duration) = end_time.duration_since(self.now) {
            duration <= self.conmmittee_term
        } else {
            false
        }
    }

    async fn broadcast_response(&self, end_time: SystemTime, is_accepted: bool) -> Result<()> {
        let payload = gossipsub::Payload::ConsensusTimeResponse {
            end_time,
            is_accepted,
        };

        self.transport
            .publish(&self.topic, payload)
            .await
            .map_err(|e| Error::Dkg(e.to_string()))?;

        Ok(())
    }
}

impl<D: Dkg> DkgGenerator<D> {
    pub fn new(transport: Arc<Transport>, dkg: Arc<D>, config: Config) -> Self {
        Self {
            transport,
            dkg,
            config,
        }
    }

    pub async fn generate(
        &self,
        id: Vec<u8>,
        epoch: u64,
        candidates: IndexedMap<libp2p::PeerId, PublicKey>,
    ) -> Result<GenerateResult> {
        self.validate_self_in_candidates(&candidates)?;
        self.initialize_dkg_peers(&candidates).await?;

        let result = self.perform_dkg_generation(id).await?;

        match result {
            dkg::GenerateResult::Success {
                secret,
                public,
                global_commitments,
            } => {
                let end_time = self.establish_consensus_time(&candidates).await?;

                let candidates = candidates
                    .iter()
                    .map(|(peer_id, _)| (*peer_id, ()))
                    .collect::<IndexedMap<_, _>>();

                let info = committee::Info::new(epoch, candidates, public, end_time);

                Ok(GenerateResult::Success {
                    info: Box::new(info),
                    secret,
                    global_commitments,
                })
            }
            dkg::GenerateResult::Failure { invalid_peers } => {
                Ok(GenerateResult::Failure(invalid_peers))
            }
        }
    }

    fn validate_self_in_candidates(
        &self,
        candidates: &IndexedMap<libp2p::PeerId, PublicKey>,
    ) -> Result<()> {
        if !candidates.contains_key(&self.transport.self_peer()) {
            return Err(Error::SelfPeerNotInCandidates);
        }
        Ok(())
    }

    async fn initialize_dkg_peers(
        &self,
        candidates: &IndexedMap<libp2p::PeerId, PublicKey>,
    ) -> Result<()> {
        self.dkg
            .set_peers(candidates.clone())
            .await
            .map_err(|e| Error::Dkg(e.to_string()))
    }

    async fn perform_dkg_generation(&self, id: Vec<u8>) -> Result<dkg::GenerateResult> {
        self.dkg
            .generate(id)
            .await
            .map_err(|e| Error::Dkg(e.to_string()))
    }

    async fn establish_consensus_time(
        &self,
        candidates: &IndexedMap<libp2p::PeerId, PublicKey>,
    ) -> Result<SystemTime> {
        let expected_peers = self.extract_expected_peers(candidates);

        for i in 0..candidates.len() {
            let proposal_peer = candidates.get_key(&i).ok_or(Error::PeerNotFound)?;

            if let Some(consensus_time) = self
                .attempt_consensus_with_proposer(*proposal_peer, &expected_peers)
                .await?
            {
                return Ok(consensus_time);
            }
        }

        Err(Error::ConsensusTimeFailed)
    }

    fn extract_expected_peers(
        &self,
        candidates: &IndexedMap<libp2p::PeerId, PublicKey>,
    ) -> HashSet<libp2p::PeerId> {
        candidates.iter().map(|(peer_id, _)| *peer_id).collect()
    }

    async fn attempt_consensus_with_proposer(
        &self,
        proposal_peer: libp2p::PeerId,
        expected_peers: &HashSet<libp2p::PeerId>,
    ) -> Result<Option<SystemTime>> {
        let now = SystemTime::now();
        let validator = self.create_validator(now, proposal_peer);

        let mut rx = self.transport.listen_on_topic(&self.config.topic).await?;
        let mut collector = self.create_consensus_collector(validator, expected_peers.clone());

        if proposal_peer == self.transport.self_peer() {
            let end_time = now + self.config.committee_term;
            self.broadcast_time_proposal(end_time).await?;
            collector =
                collector.with_initial_item(&(end_time, true), self.transport.self_peer())?;
        }

        match collector.collect(&mut rx).await? {
            Some((end_time, is_accepted)) if is_accepted => Ok(Some(end_time)),
            _ => Ok(None),
        }
    }

    fn create_validator(&self, now: SystemTime, proposal_peer: libp2p::PeerId) -> Validator {
        Validator {
            transport: self.transport.clone(),
            proposal_peer,
            now,
            topic: self.config.topic.clone(),
            conmmittee_term: self.config.committee_term,
        }
    }

    fn create_consensus_collector(
        &self,
        validator: Validator,
        expected_peers: HashSet<libp2p::PeerId>,
    ) -> ConsensusCollector<(SystemTime, bool), Error, Validator> {
        ConsensusCollector::new(
            validator,
            self.config.network_latency,
            self.config.threshold_counter,
        )
        .with_expected_peers(expected_peers)
    }

    async fn broadcast_time_proposal(&self, end_time: SystemTime) -> Result<()> {
        let payload = gossipsub::Payload::ConsensusTime { end_time };
        self.transport.publish(&self.config.topic, payload).await?;
        Ok(())
    }
}

impl consensus_collector::Validator<(SystemTime, bool), Error> for Validator {
    async fn validate(
        &mut self,
        message: gossipsub::Message,
    ) -> Result<Option<(SystemTime, bool)>> {
        match message.payload {
            gossipsub::Payload::ConsensusTime { end_time } => {
                if self.proposal_peer == message.source {
                    let is_accepted = self.validate_time(end_time);
                    self.broadcast_response(end_time, is_accepted).await?;
                    Ok(Some((end_time, true)))
                } else {
                    Ok(None)
                }
            }
            gossipsub::Payload::ConsensusTimeResponse {
                end_time,
                is_accepted,
            } => Ok(Some((end_time, is_accepted))),
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::transport::MockTransport;
    use crate::{crypto::dkg::MockDkg, mocks::MockError};
    use crate::{
        crypto::keypair::{self, PublicKey},
        utils::consensus_collector::Validator as _,
    };
    use mockall::predicate::*;
    use std::time::{Duration, SystemTime};

    fn create_test_config() -> Config {
        Config {
            topic: "test-topic".to_string(),
            network_latency: tokio::time::Duration::from_secs(1),
            committee_term: tokio::time::Duration::from_secs(30),
            threshold_counter: threshold::Counter::default(),
        }
    }

    fn create_mock_transport(self_peer: libp2p::PeerId) -> Arc<MockTransport> {
        let mut mock = MockTransport::default();
        mock.expect_self_peer().return_const(self_peer);
        Arc::new(mock)
    }

    fn create_mock_dkg() -> Arc<MockDkg> {
        Arc::new(MockDkg::new())
    }

    fn create_candidates(peers: Vec<libp2p::PeerId>) -> IndexedMap<libp2p::PeerId, PublicKey> {
        let mut candidates = IndexedMap::new();
        for peer in peers {
            let (_, pk) = keypair::generate_secp256k1();
            candidates.insert(peer, pk);
        }
        candidates
    }

    fn create_message_id() -> libp2p::gossipsub::MessageId {
        const MESSAGE_ID: [u8; 32] = [0; 32];
        libp2p::gossipsub::MessageId::from(MESSAGE_ID)
    }

    #[test]
    fn new_creates_dkg_generator_with_correct_configuration() {
        let self_peer = libp2p::PeerId::random();
        let transport = create_mock_transport(self_peer);
        let dkg = create_mock_dkg();
        let config = create_test_config();

        let generator = DkgGenerator::new(transport, dkg, config.clone());

        assert_eq!(generator.config.topic, config.topic);
        assert_eq!(generator.config.network_latency, config.network_latency);
        assert_eq!(generator.config.committee_term, config.committee_term);
    }

    #[tokio::test]
    async fn validate_self_in_candidates_should_succeed_when_self_present() {
        let self_peer = libp2p::PeerId::random();
        let transport = create_mock_transport(self_peer);
        let dkg = create_mock_dkg();
        let config = create_test_config();

        let generator = DkgGenerator::new(transport, dkg, config);
        let candidates = create_candidates(vec![self_peer]);

        let result = generator.validate_self_in_candidates(&candidates);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn validate_self_in_candidates_should_fail_when_self_missing() {
        let self_peer = libp2p::PeerId::random();
        let other_peer = libp2p::PeerId::random();
        let transport = create_mock_transport(self_peer);
        let dkg = create_mock_dkg();
        let config = create_test_config();

        let generator = DkgGenerator::new(transport, dkg, config);
        let candidates = create_candidates(vec![other_peer]); // missing self_peer

        let result = generator.validate_self_in_candidates(&candidates);
        assert!(matches!(result, Err(Error::SelfPeerNotInCandidates)));
    }

    #[tokio::test]
    async fn initialize_dkg_peers_should_call_set_peers() {
        let self_peer = libp2p::PeerId::random();
        let transport = create_mock_transport(self_peer);

        let mut mock_dkg = MockDkg::new();
        mock_dkg
            .expect_set_peers()
            .with(always())
            .times(1)
            .returning(|_| Ok(()));

        let dkg = Arc::new(mock_dkg);
        let config = create_test_config();

        let generator = DkgGenerator::new(transport, dkg, config);
        let candidates = create_candidates(vec![self_peer]);

        let result = generator.initialize_dkg_peers(&candidates).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn initialize_dkg_peers_should_propagate_error() {
        let self_peer = libp2p::PeerId::random();
        let transport = create_mock_transport(self_peer);

        let mut mock_dkg = MockDkg::new();
        mock_dkg
            .expect_set_peers()
            .with(always())
            .times(1)
            .returning(|_| Err(MockError));

        let dkg = Arc::new(mock_dkg);
        let config = create_test_config();

        let generator = DkgGenerator::new(transport, dkg, config);
        let candidates = create_candidates(vec![self_peer]);

        let result = generator.initialize_dkg_peers(&candidates).await;
        assert!(matches!(result, Err(Error::Dkg(_))));
    }

    #[tokio::test]
    async fn perform_dkg_generation_should_succeed() {
        let self_peer = libp2p::PeerId::random();
        let transport = create_mock_transport(self_peer);

        let mut mock_dkg = MockDkg::new();
        mock_dkg
            .expect_generate()
            .with(eq(b"test-id".to_vec()))
            .times(1)
            .returning(|_| {
                Ok(dkg::GenerateResult::Success {
                    secret: Scalar::secp256k1_zero(),
                    public: Point::secp256k1_zero(),
                    global_commitments: vec![Point::secp256k1_zero()],
                })
            });

        let dkg = Arc::new(mock_dkg);
        let config = create_test_config();

        let generator = DkgGenerator::new(transport, dkg, config);

        let result = generator.perform_dkg_generation(b"test-id".to_vec()).await;
        assert!(result.is_ok());
        match result.unwrap() {
            dkg::GenerateResult::Success { .. } => {}
            _ => panic!("Expected Success result"),
        }
    }

    #[tokio::test]
    async fn perform_dkg_generation_should_handle_failure() {
        let self_peer = libp2p::PeerId::random();
        let other_peer = libp2p::PeerId::random();
        let transport = create_mock_transport(self_peer);

        let mut mock_dkg = MockDkg::new();
        mock_dkg.expect_generate().times(1).returning(move |_| {
            let mut invalid_peers = HashSet::new();
            invalid_peers.insert(other_peer);
            Ok(dkg::GenerateResult::Failure { invalid_peers })
        });

        let dkg = Arc::new(mock_dkg);
        let config = create_test_config();

        let generator = DkgGenerator::new(transport, dkg, config);

        let result = generator.perform_dkg_generation(b"test-id".to_vec()).await;
        assert!(result.is_ok());
        match result.unwrap() {
            dkg::GenerateResult::Failure { invalid_peers } => {
                assert_eq!(invalid_peers.len(), 1);
                assert!(invalid_peers.contains(&other_peer));
            }
            _ => panic!("Expected Failure result"),
        }
    }

    #[test]
    fn validator_validate_time_should_accept_valid_times() {
        const COMMITTEE_TERM: u64 = 60;
        let self_peer = libp2p::PeerId::random();
        let transport = create_mock_transport(self_peer);
        let now = SystemTime::now();
        let committee_term = tokio::time::Duration::from_secs(COMMITTEE_TERM);

        let validator = Validator {
            transport,
            proposal_peer: libp2p::PeerId::random(),
            now,
            topic: "test-topic".to_string(),
            conmmittee_term: committee_term,
        };

        assert!(validator.validate_time(now + Duration::from_secs(COMMITTEE_TERM - 1)));
        assert!(validator.validate_time(now + Duration::from_secs(COMMITTEE_TERM)));
    }

    #[test]
    fn validator_validate_time_should_reject_invalid_times() {
        const COMMITTEE_TERM: u64 = 60;

        let self_peer = libp2p::PeerId::random();
        let transport = create_mock_transport(self_peer);
        let now = SystemTime::now();
        let committee_term = tokio::time::Duration::from_secs(COMMITTEE_TERM);

        let validator = Validator {
            transport,
            proposal_peer: libp2p::PeerId::random(),
            now,
            topic: "test-topic".to_string(),
            conmmittee_term: committee_term,
        };

        assert!(!validator.validate_time(now + Duration::from_secs(COMMITTEE_TERM + 1)));
    }

    #[tokio::test]
    async fn validator_should_process_consensus_time_from_proposal_peer() {
        const COMMITTEE_TERM: u64 = 60;

        let self_peer = libp2p::PeerId::random();
        let proposal_peer = libp2p::PeerId::random();
        let mut mock_transport = MockTransport::default();
        mock_transport.expect_self_peer().return_const(self_peer);

        mock_transport
            .expect_publish()
            .with(eq("test-topic".to_string()), always())
            .times(1)
            .returning(|_, _| Ok(create_message_id()));

        let transport = Arc::new(mock_transport);
        let now = SystemTime::now();
        let end_time = now + Duration::from_secs(COMMITTEE_TERM);

        let mut validator = Validator {
            transport,
            proposal_peer,
            now,
            topic: "test-topic".to_string(),
            conmmittee_term: tokio::time::Duration::from_secs(COMMITTEE_TERM),
        };

        let message = gossipsub::Message {
            message_id: create_message_id(),
            topic: "test-topic".to_string(),
            source: proposal_peer,
            payload: gossipsub::Payload::ConsensusTime { end_time },
            committee_signature: None,
        };

        let result = validator.validate(message).await;

        assert!(result.is_ok());
        if let Ok(Some((validated_end_time, is_accepted))) = result {
            assert_eq!(validated_end_time, end_time);
            assert!(is_accepted);
        } else {
            panic!("Expected Some((end_time, true))");
        }
    }

    #[tokio::test]
    async fn validator_should_ignore_consensus_time_not_from_proposal_peer() {
        const COMMITTEE_TERM: u64 = 60;

        let self_peer = libp2p::PeerId::random();
        let proposal_peer = libp2p::PeerId::random();
        let other_peer = libp2p::PeerId::random();
        let transport = create_mock_transport(self_peer);
        let now = SystemTime::now();

        let mut validator = Validator {
            transport,
            proposal_peer,
            now,
            topic: "test-topic".to_string(),
            conmmittee_term: tokio::time::Duration::from_secs(COMMITTEE_TERM),
        };

        let message = gossipsub::Message {
            message_id: create_message_id(),
            source: other_peer,
            payload: gossipsub::Payload::ConsensusTime {
                end_time: now + Duration::from_secs(COMMITTEE_TERM),
            },
            topic: "test-topic".to_string(),
            committee_signature: None,
        };

        let result = validator.validate(message).await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }
}
