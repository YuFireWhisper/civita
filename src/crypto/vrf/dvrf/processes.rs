use dashmap::{
    mapref::one::{Ref, RefMut},
    DashMap,
};
use libp2p::{gossipsub::MessageId, PeerId};
use std::sync::Arc;
use thiserror::Error;
use tokio::time::{Duration, Instant};

use super::consensus_process::{self, ConsensusProcess, ConsensusProcessFactory, ProcessStatus};

#[derive(Debug, Error)]
pub enum Error {
    #[error("Process not found")]
    ProcessNotFound,
    #[error("Process error: {0}")]
    Process(#[from] consensus_process::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct Processes {
    processes: DashMap<MessageId, Box<dyn ConsensusProcess>>,
    vrf_proof_duration: Duration,
    vrf_vote_duration: Duration,
    process_factory: Arc<dyn ConsensusProcessFactory>,
}

impl Processes {
    pub fn new(
        vrf_proof_duration: Duration,
        vrf_vote_duration: Duration,
        process_factory: Arc<dyn ConsensusProcessFactory>,
    ) -> Self {
        let processes = DashMap::new();
        Self {
            processes,
            vrf_proof_duration,
            vrf_vote_duration,
            process_factory,
        }
    }

    pub fn insert_peer_and_proof(
        &self,
        message_id: MessageId,
        peer_id: PeerId,
        proof: Vec<u8>,
    ) -> Result<()> {
        let mut process = self.processes.entry(message_id).or_insert_with(|| {
            self.process_factory
                .create(self.vrf_proof_duration, self.vrf_vote_duration)
        });

        process.insert_voter(peer_id)?;
        process.insert_proof(proof)?;
        Ok(())
    }

    pub fn calculate_consensus(&self, message_id: &MessageId) -> Result<[u8; 32]> {
        self.processes
            .get_mut(message_id)
            .ok_or(Error::ProcessNotFound)?
            .calculate_consensus()
            .map_err(Error::from)
    }

    fn get_process_mut(
        &self,
        message_id: &MessageId,
    ) -> Result<RefMut<'_, MessageId, Box<dyn ConsensusProcess>>> {
        self.processes
            .get_mut(message_id)
            .ok_or(Error::ProcessNotFound)
    }

    pub fn insert_completion_vote(
        &self,
        message_id: &MessageId,
        peer_id: PeerId,
        random: [u8; 32],
    ) -> Result<Option<[u8; 32]>> {
        self.get_process_mut(message_id)?
            .insert_completion_vote(peer_id, random)
            .map_err(Error::from)
    }

    pub fn insert_failure_vote(&self, message_id: &MessageId, peer_id: PeerId) -> Result<bool> {
        self.get_process_mut(message_id)?
            .insert_failure_vote(peer_id)
            .map_err(Error::from)
    }

    pub fn status(&self, message_id: &MessageId) -> Result<ProcessStatus> {
        Ok(self.get_process_mut(message_id)?.status())
    }

    pub fn proof_deadline(&self, message_id: &MessageId) -> Result<Instant> {
        Ok(self.get_process(message_id)?.proof_deadline())
    }

    fn get_process(
        &self,
        message_id: &MessageId,
    ) -> Result<Ref<'_, MessageId, Box<dyn ConsensusProcess>>> {
        self.processes.get(message_id).ok_or(Error::ProcessNotFound)
    }

    pub fn vote_deadline(&self, message_id: &MessageId) -> Result<Instant> {
        Ok(self.get_process(message_id)?.vote_deadline())
    }

    pub fn random(&self, message_id: &MessageId) -> Result<Option<[u8; 32]>> {
        Ok(self.get_process(message_id)?.random())
    }

    pub fn update_all_status(&self) -> Vec<MessageId> {
        let mut failed = Vec::new();

        self.processes.retain(|message_id, process| {
            let status = process.update_status();
            if status == ProcessStatus::Failed {
                failed.push(message_id.clone());
                false
            } else {
                true
            }
        });

        failed
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::fmt::Debug;
    use std::sync::Arc;

    use libp2p::gossipsub::MessageId;
    use libp2p::PeerId;
    use mockall::mock;
    use tokio::time::{Duration, Instant};

    use crate::crypto::vrf::dvrf::consensus_process::{
        ConsensusProcess, ConsensusProcessFactory, Error, ProcessStatus,
    };

    use super::Processes;

    mock! {
        pub ConsensusProcess {}

        impl ConsensusProcess for ConsensusProcess {
            fn insert_voter(&mut self, peer_id: PeerId) -> Result<(), Error>;
            fn insert_proof(&mut self, proof: Vec<u8>) -> Result<(), Error>;
            fn calculate_consensus(&self) -> Result<[u8; 32], Error>;
            fn insert_completion_vote(&mut self, peer_id: PeerId, random: [u8; 32]) -> Result<Option<[u8; 32]>, Error>;
            fn insert_failure_vote(&mut self, peer_id: PeerId) -> Result<bool, Error>;
            fn is_proof_timeout(&self) -> bool;
            fn is_vote_timeout(&self) -> bool;
            fn status(&mut self) -> ProcessStatus;
            fn update_status(&mut self) -> ProcessStatus;
            fn proof_deadline(&self) -> Instant;
            fn vote_deadline(&self) -> Instant;
            fn random(&self) -> Option<[u8; 32]>;
        }

        impl Clone for ConsensusProcess {
            fn clone(&self) -> Self;
        }
    }

    mock! {
        pub ConsensusProcessFactory {}

        impl ConsensusProcessFactory for ConsensusProcessFactory {
            fn create(&self, proof_duration: Duration, vote_duration: Duration) -> Box<dyn ConsensusProcess>;
        }

        impl Clone for ConsensusProcessFactory {
            fn clone(&self) -> Self;
        }
    }

    struct TestFixture {
        factory: MockConsensusProcessFactory,
        proof_duration: Duration,
        vote_duration: Duration,
        message_id: MessageId,
        peer_id: PeerId,
    }

    impl TestFixture {
        const PROOF_DURATION: Duration = Duration::from_millis(10);
        const VOTE_DURATION: Duration = Duration::from_millis(20);
        const MESSAGE_ID_STR: &str = "message_id";

        fn new() -> Self {
            let factory = MockConsensusProcessFactory::new();
            let proof_duration = Self::PROOF_DURATION;
            let vote_duration = Self::VOTE_DURATION;
            let message_id = MessageId::from(Self::MESSAGE_ID_STR);
            let peer_id = PeerId::random();
            Self {
                factory,
                proof_duration,
                vote_duration,
                message_id,
                peer_id,
            }
        }

        fn setup_mock_process(&mut self) -> MockConsensusProcess {
            MockConsensusProcess::new()
        }

        fn expect_create_process(&mut self, mock_process: MockConsensusProcess) {
            let mp_cell = RefCell::new(Some(mock_process));

            self.factory
                .expect_clone()
                .returning(MockConsensusProcessFactory::default);

            self.factory
                .expect_create()
                .with(
                    mockall::predicate::eq(self.proof_duration),
                    mockall::predicate::eq(self.vote_duration),
                )
                .times(1)
                .returning(move |_, _| Box::new(mp_cell.borrow_mut().take().unwrap()));
        }

        fn create_processes_with_mock(&mut self, mock_process: MockConsensusProcess) -> Processes {
            self.expect_create_process(mock_process);
            let arc_factory: Arc<dyn ConsensusProcessFactory> = Arc::new(self.factory.clone());
            let processes = Processes::new(
                self.proof_duration,
                self.vote_duration,
                Arc::clone(&arc_factory),
            );

            processes.processes.insert(
                self.message_id.clone(),
                self.factory.create(self.proof_duration, self.vote_duration),
            );

            processes
        }

        fn create_empty_processes(&mut self) -> Processes {
            self.factory
                .expect_clone()
                .returning(MockConsensusProcessFactory::default);

            let arc_factory: Arc<dyn ConsensusProcessFactory> = Arc::new(self.factory.clone());
            Processes::new(
                self.proof_duration,
                self.vote_duration,
                Arc::clone(&arc_factory),
            )
        }

        fn assert_process_not_found<T: Debug>(result: Result<T, super::Error>) {
            match result {
                Err(super::Error::ProcessNotFound) => (),
                _ => panic!("Expected ProcessNotFound error, got: {:?}", result),
            }
        }

        fn assert_process_error<T: Debug>(result: Result<T, super::Error>, expected_error: Error) {
            match result {
                Err(super::Error::Process(error)) => {
                    assert!(
                        std::mem::discriminant(&error) == std::mem::discriminant(&expected_error),
                        "Expected {:?}, got {:?}",
                        expected_error,
                        error
                    );
                }
                other => panic!("Expected Process error, got: {:?}", other),
            }
        }
    }

    #[test]
    fn test_new() {
        let mut fixture = TestFixture::new();
        let processes = fixture.create_empty_processes();
        assert!(processes.processes.is_empty());
    }

    #[test]
    fn test_insert_peer_and_proof_success() {
        let mut fixture = TestFixture::new();
        let mut mock_process = fixture.setup_mock_process();

        mock_process
            .expect_insert_voter()
            .with(mockall::predicate::eq(fixture.peer_id))
            .times(1)
            .returning(|_| Ok(()));
        mock_process
            .expect_insert_proof()
            .with(mockall::predicate::eq(vec![1, 2, 3]))
            .times(1)
            .returning(|_| Ok(()));

        fixture.expect_create_process(mock_process);

        let arc_factory: Arc<dyn ConsensusProcessFactory> = Arc::new(fixture.factory);
        let processes = Processes::new(fixture.proof_duration, fixture.vote_duration, arc_factory);
        let result =
            processes.insert_peer_and_proof(fixture.message_id, fixture.peer_id, vec![1, 2, 3]);

        assert!(result.is_ok());
    }

    #[test]
    fn test_insert_peer_and_proof_voter_error() {
        let mut fixture = TestFixture::new();
        let mut mock_process = fixture.setup_mock_process();

        mock_process
            .expect_insert_voter()
            .with(mockall::predicate::eq(fixture.peer_id))
            .times(1)
            .returning(|_| Err(Error::DuplicatePeerId(PeerId::random())));

        fixture.expect_create_process(mock_process);

        let arc_factory: Arc<dyn ConsensusProcessFactory> = Arc::new(fixture.factory);
        let processes = Processes::new(fixture.proof_duration, fixture.vote_duration, arc_factory);
        let result =
            processes.insert_peer_and_proof(fixture.message_id, fixture.peer_id, vec![1, 2, 3]);

        TestFixture::assert_process_error(result, Error::DuplicatePeerId(PeerId::random()));
    }

    #[test]
    fn test_insert_peer_and_proof_proof_error() {
        let mut fixture = TestFixture::new();
        let mut mock_process = fixture.setup_mock_process();

        mock_process
            .expect_insert_voter()
            .with(mockall::predicate::eq(fixture.peer_id))
            .times(1)
            .returning(|_| Ok(()));
        mock_process
            .expect_insert_proof()
            .with(mockall::predicate::eq(vec![1, 2, 3]))
            .times(1)
            .returning(|_| Err(Error::InsufficientProofs));

        fixture.expect_create_process(mock_process);

        let arc_factory: Arc<dyn ConsensusProcessFactory> = Arc::new(fixture.factory);
        let processes = Processes::new(fixture.proof_duration, fixture.vote_duration, arc_factory);
        let result =
            processes.insert_peer_and_proof(fixture.message_id, fixture.peer_id, vec![1, 2, 3]);

        TestFixture::assert_process_error(result, Error::InsufficientProofs);
    }

    #[test]
    fn test_calculate_consensus_success() {
        let mut fixture = TestFixture::new();
        let mut mock_process = fixture.setup_mock_process();
        let expected_result = [42u8; 32];

        mock_process
            .expect_calculate_consensus()
            .times(1)
            .returning(move || Ok(expected_result));

        let processes = fixture.create_processes_with_mock(mock_process);
        let result = processes.calculate_consensus(&fixture.message_id);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_result);
    }

    #[test]
    fn test_calculate_consensus_process_error() {
        let mut fixture = TestFixture::new();
        let mut mock_process = fixture.setup_mock_process();

        mock_process
            .expect_calculate_consensus()
            .times(1)
            .returning(|| Err(Error::InsufficientProofs));

        let processes = fixture.create_processes_with_mock(mock_process);
        let result = processes.calculate_consensus(&fixture.message_id);

        TestFixture::assert_process_error(result, Error::InsufficientProofs);
    }

    #[test]
    fn test_calculate_consensus_not_found() {
        let mut fixture = TestFixture::new();
        let processes = fixture.create_empty_processes();
        let result = processes.calculate_consensus(&fixture.message_id);

        TestFixture::assert_process_not_found(result);
    }

    #[test]
    fn test_insert_completion_vote_success() {
        let mut fixture = TestFixture::new();
        let mut mock_process = fixture.setup_mock_process();
        let random = [42u8; 32];
        let expected_result = Some([42u8; 32]);

        mock_process
            .expect_insert_completion_vote()
            .with(
                mockall::predicate::eq(fixture.peer_id),
                mockall::predicate::eq(random),
            )
            .times(1)
            .returning(move |_, _| Ok(expected_result));

        let processes = fixture.create_processes_with_mock(mock_process);
        let result = processes.insert_completion_vote(&fixture.message_id, fixture.peer_id, random);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_result);
    }

    #[test]
    fn test_insert_completion_vote_not_found() {
        let mut fixture = TestFixture::new();
        let processes = fixture.create_empty_processes();
        let result =
            processes.insert_completion_vote(&fixture.message_id, fixture.peer_id, [42u8; 32]);

        TestFixture::assert_process_not_found(result);
    }

    #[test]
    fn test_insert_failure_vote_success() {
        let mut fixture = TestFixture::new();
        let mut mock_process = fixture.setup_mock_process();

        mock_process
            .expect_insert_failure_vote()
            .with(mockall::predicate::eq(fixture.peer_id))
            .times(1)
            .returning(|_| Ok(true));

        let processes = fixture.create_processes_with_mock(mock_process);
        let result = processes.insert_failure_vote(&fixture.message_id, fixture.peer_id);

        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_insert_failure_vote_not_found() {
        let mut fixture = TestFixture::new();
        let processes = fixture.create_empty_processes();
        let result = processes.insert_failure_vote(&fixture.message_id, fixture.peer_id);

        TestFixture::assert_process_not_found(result);
    }

    #[test]
    fn test_status() {
        let mut fixture = TestFixture::new();
        let mut mock_process = fixture.setup_mock_process();

        mock_process
            .expect_status()
            .times(1)
            .returning(|| ProcessStatus::InProgress);

        let processes = fixture.create_processes_with_mock(mock_process);
        let result = processes.status(&fixture.message_id);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ProcessStatus::InProgress);
    }

    #[test]
    fn test_proof_deadline() {
        let mut fixture = TestFixture::new();
        let mut mock_process = fixture.setup_mock_process();
        let now = Instant::now();

        mock_process
            .expect_proof_deadline()
            .times(1)
            .returning(move || now);

        let processes = fixture.create_processes_with_mock(mock_process);
        let result = processes.proof_deadline(&fixture.message_id);

        assert!(result.is_ok());
    }

    #[test]
    fn test_vote_deadline() {
        let mut fixture = TestFixture::new();
        let mut mock_process = fixture.setup_mock_process();
        let now = Instant::now();

        mock_process
            .expect_vote_deadline()
            .times(1)
            .returning(move || now);

        let processes = fixture.create_processes_with_mock(mock_process);
        let result = processes.vote_deadline(&fixture.message_id);

        assert!(result.is_ok());
    }

    #[test]
    fn test_random() {
        let mut fixture = TestFixture::new();
        let mut mock_process = fixture.setup_mock_process();
        let random_value = Some([42u8; 32]);

        mock_process
            .expect_random()
            .times(1)
            .returning(move || random_value);

        let processes = fixture.create_processes_with_mock(mock_process);
        let result = processes.random(&fixture.message_id);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), random_value);
    }

    #[test]
    fn test_update_all_status_none_failed() {
        let mut fixture = TestFixture::new();
        let mut mock_process = fixture.setup_mock_process();

        mock_process
            .expect_update_status()
            .times(1)
            .returning(|| ProcessStatus::InProgress);

        let processes = fixture.create_processes_with_mock(mock_process);
        let failed = processes.update_all_status();

        assert!(failed.is_empty());
        assert!(processes.processes.contains_key(&fixture.message_id));
    }

    #[test]
    fn test_update_all_status_some_failed() {
        let mut fixture = TestFixture::new();
        let mut mock_process = fixture.setup_mock_process();

        mock_process
            .expect_update_status()
            .times(1)
            .returning(|| ProcessStatus::Failed);

        let processes = fixture.create_processes_with_mock(mock_process);
        let failed = processes.update_all_status();

        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0], fixture.message_id);
        assert!(!processes.processes.contains_key(&fixture.message_id));
    }
}
