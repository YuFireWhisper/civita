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
    use std::sync::Arc;

    use libp2p::gossipsub::MessageId;
    use libp2p::PeerId;
    use mockall::mock;
    use tokio::time::{Duration, Instant};

    use crate::crypto::vrf::consensus_process::Error;
    use crate::crypto::vrf::consensus_process::{
        ConsensusProcess, ConsensusProcessFactory, ProcessStatus,
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

    fn create_processes() -> (MockConsensusProcessFactory, Duration, Duration) {
        let factory = MockConsensusProcessFactory::new();
        let proof_duration = Duration::from_secs(10);
        let vote_duration = Duration::from_secs(20);
        (factory, proof_duration, vote_duration)
    }

    #[test]
    fn test_new() {
        let (factory, proof_duration, vote_duration) = create_processes();
        // 不需要設定 factory.clone() 的期望
        let arc_factory: Arc<dyn ConsensusProcessFactory> = Arc::new(factory);
        let processes = Processes::new(proof_duration, vote_duration, Arc::clone(&arc_factory));
        assert!(processes.processes.is_empty());
    }

    #[test]
    fn test_insert_peer_and_proof_success() {
        let (mut factory, proof_duration, vote_duration) = create_processes();
        let message_id = MessageId::new(b"test-message-id");
        let peer_id = PeerId::random();

        let mut mp = MockConsensusProcess::new();
        mp.expect_insert_voter()
            .with(mockall::predicate::eq(peer_id))
            .times(1)
            .returning(|_| Ok(()));
        mp.expect_insert_proof()
            .with(mockall::predicate::eq(vec![1, 2, 3]))
            .times(1)
            .returning(|_| Ok(()));

        let mp_cell = RefCell::new(Some(mp));
        factory
            .expect_create()
            .times(1)
            .returning(move |_, _| Box::new(mp_cell.borrow_mut().take().unwrap()));

        let arc_factory: Arc<dyn ConsensusProcessFactory> = Arc::new(factory);
        let processes = Processes::new(proof_duration, vote_duration, Arc::clone(&arc_factory));
        let result = processes.insert_peer_and_proof(message_id, peer_id, vec![1, 2, 3]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_insert_peer_and_proof_voter_error() {
        let (mut factory, proof_duration, vote_duration) = create_processes();
        let message_id = MessageId::new(b"test-message-id");
        let peer_id = PeerId::random();

        let mut mp = MockConsensusProcess::new();
        mp.expect_insert_voter()
            .with(mockall::predicate::eq(peer_id))
            .times(1)
            .returning(|_| Err(Error::DuplicatePeerId(PeerId::random())));

        let mp_cell = RefCell::new(Some(mp));
        factory
            .expect_create()
            .times(1)
            .returning(move |_, _| Box::new(mp_cell.borrow_mut().take().unwrap()));

        let arc_factory: Arc<dyn ConsensusProcessFactory> = Arc::new(factory);
        let processes = Processes::new(proof_duration, vote_duration, Arc::clone(&arc_factory));
        let result = processes.insert_peer_and_proof(message_id, peer_id, vec![1, 2, 3]);
        assert!(result.is_err());
        match result.unwrap_err() {
            super::Error::Process(Error::DuplicatePeerId(_)) => (),
            e => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_insert_peer_and_proof_proof_error() {
        let (mut factory, proof_duration, vote_duration) = create_processes();
        let message_id = MessageId::new(b"test-message-id");
        let peer_id = PeerId::random();

        let mut mp = MockConsensusProcess::new();
        mp.expect_insert_voter()
            .with(mockall::predicate::eq(peer_id))
            .times(1)
            .returning(|_| Ok(()));
        mp.expect_insert_proof()
            .with(mockall::predicate::eq(vec![1, 2, 3]))
            .times(1)
            .returning(|_| Err(Error::DuplicateProof));

        let mp_cell = RefCell::new(Some(mp));
        factory
            .expect_create()
            .times(1)
            .returning(move |_, _| Box::new(mp_cell.borrow_mut().take().unwrap()));

        let arc_factory: Arc<dyn ConsensusProcessFactory> = Arc::new(factory);
        let processes = Processes::new(proof_duration, vote_duration, Arc::clone(&arc_factory));
        let result = processes.insert_peer_and_proof(message_id, peer_id, vec![1, 2, 3]);
        assert!(result.is_err());
        match result.unwrap_err() {
            super::Error::Process(Error::DuplicateProof) => (),
            e => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_calculate_consensus_success() {
        let (mut factory, proof_duration, vote_duration) = create_processes();
        let message_id = MessageId::new(b"test-message-id");
        let expected_result = [42u8; 32];

        let mut mp = MockConsensusProcess::new();
        mp.expect_calculate_consensus()
            .times(1)
            .returning(move || Ok(expected_result));

        let mp_cell = RefCell::new(Some(mp));
        factory
            .expect_create()
            .times(1)
            .returning(move |_, _| Box::new(mp_cell.borrow_mut().take().unwrap()));

        let arc_factory: Arc<dyn ConsensusProcessFactory> = Arc::new(factory);
        let processes = Processes::new(proof_duration, vote_duration, Arc::clone(&arc_factory));

        processes.processes.insert(
            message_id.clone(),
            arc_factory.create(Duration::from_secs(10), Duration::from_secs(20)),
        );

        let result = processes.calculate_consensus(&message_id);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_result);
    }

    #[test]
    fn test_calculate_consensus_process_error() {
        let (mut factory, proof_duration, vote_duration) = create_processes();
        let message_id = MessageId::new(b"test-message-id");

        let mut mp = MockConsensusProcess::new();
        mp.expect_calculate_consensus()
            .times(1)
            .returning(|| Err(Error::InsufficientProofs));

        let mp_cell = RefCell::new(Some(mp));
        factory
            .expect_create()
            .times(1)
            .returning(move |_, _| Box::new(mp_cell.borrow_mut().take().unwrap()));

        let arc_factory: Arc<dyn ConsensusProcessFactory> = Arc::new(factory);
        let processes = Processes::new(proof_duration, vote_duration, Arc::clone(&arc_factory));

        processes.processes.insert(
            message_id.clone(),
            arc_factory.create(Duration::from_secs(10), Duration::from_secs(20)),
        );

        let result = processes.calculate_consensus(&message_id);
        assert!(result.is_err());
        match result.unwrap_err() {
            super::Error::Process(Error::InsufficientProofs) => (),
            e => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_calculate_consensus_not_found() {
        let (factory, proof_duration, vote_duration) = create_processes();
        let message_id = MessageId::new(b"test-message-id");
        let arc_factory: Arc<dyn ConsensusProcessFactory> = Arc::new(factory);
        let processes = Processes::new(proof_duration, vote_duration, Arc::clone(&arc_factory));
        let result = processes.calculate_consensus(&message_id);
        assert!(result.is_err());
        match result.unwrap_err() {
            super::Error::ProcessNotFound => (),
            e => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_insert_completion_vote_success() {
        let (mut factory, proof_duration, vote_duration) = create_processes();
        let message_id = MessageId::new(b"test-message-id");
        let peer_id = PeerId::random();
        let random = [42u8; 32];
        let expected_result = Some([42u8; 32]);

        let mut mp = MockConsensusProcess::new();
        mp.expect_insert_completion_vote()
            .with(
                mockall::predicate::eq(peer_id),
                mockall::predicate::eq(random),
            )
            .times(1)
            .returning(move |_, _| Ok(expected_result));

        let mp_cell = RefCell::new(Some(mp));
        factory
            .expect_create()
            .times(1)
            .returning(move |_, _| Box::new(mp_cell.borrow_mut().take().unwrap()));

        let arc_factory: Arc<dyn ConsensusProcessFactory> = Arc::new(factory);
        let processes = Processes::new(proof_duration, vote_duration, Arc::clone(&arc_factory));

        processes.processes.insert(
            message_id.clone(),
            arc_factory.create(Duration::from_secs(10), Duration::from_secs(20)),
        );

        let result = processes.insert_completion_vote(&message_id, peer_id, random);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_result);
    }

    #[test]
    fn test_insert_completion_vote_not_found() {
        let (factory, proof_duration, vote_duration) = create_processes();
        let message_id = MessageId::new(b"test-message-id");
        let peer_id = PeerId::random();
        let arc_factory: Arc<dyn ConsensusProcessFactory> = Arc::new(factory);
        let processes = Processes::new(proof_duration, vote_duration, Arc::clone(&arc_factory));
        let result = processes.insert_completion_vote(&message_id, peer_id, [42u8; 32]);
        assert!(result.is_err());
        match result.unwrap_err() {
            super::Error::ProcessNotFound => (),
            e => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_insert_failure_vote_success() {
        let (mut factory, proof_duration, vote_duration) = create_processes();
        let message_id = MessageId::new(b"test-message-id");
        let peer_id = PeerId::random();

        let mut mp = MockConsensusProcess::new();
        mp.expect_insert_failure_vote()
            .with(mockall::predicate::eq(peer_id))
            .times(1)
            .returning(|_| Ok(true));

        let mp_cell = RefCell::new(Some(mp));
        factory
            .expect_create()
            .times(1)
            .returning(move |_, _| Box::new(mp_cell.borrow_mut().take().unwrap()));

        let arc_factory: Arc<dyn ConsensusProcessFactory> = Arc::new(factory);
        let processes = Processes::new(proof_duration, vote_duration, Arc::clone(&arc_factory));

        processes.processes.insert(
            message_id.clone(),
            arc_factory.create(Duration::from_secs(10), Duration::from_secs(20)),
        );

        let result = processes.insert_failure_vote(&message_id, peer_id);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_insert_failure_vote_not_found() {
        let (factory, proof_duration, vote_duration) = create_processes();
        let message_id = MessageId::new(b"test-message-id");
        let peer_id = PeerId::random();
        let arc_factory: Arc<dyn ConsensusProcessFactory> = Arc::new(factory);
        let processes = Processes::new(proof_duration, vote_duration, Arc::clone(&arc_factory));
        let result = processes.insert_failure_vote(&message_id, peer_id);
        assert!(result.is_err());
        match result.unwrap_err() {
            super::Error::ProcessNotFound => (),
            e => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_status() {
        let (mut factory, proof_duration, vote_duration) = create_processes();
        let message_id = MessageId::new(b"test-message-id");

        let mut mp = MockConsensusProcess::new();
        mp.expect_status()
            .times(1)
            .returning(|| ProcessStatus::InProgress);

        let mp_cell = RefCell::new(Some(mp));
        factory
            .expect_create()
            .times(1)
            .returning(move |_, _| Box::new(mp_cell.borrow_mut().take().unwrap()));

        let arc_factory: Arc<dyn ConsensusProcessFactory> = Arc::new(factory);
        let processes = Processes::new(proof_duration, vote_duration, Arc::clone(&arc_factory));

        processes.processes.insert(
            message_id.clone(),
            arc_factory.create(Duration::from_secs(10), Duration::from_secs(20)),
        );

        let result = processes.status(&message_id);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ProcessStatus::InProgress);
    }

    #[test]
    fn test_proof_deadline() {
        let (mut factory, proof_duration, vote_duration) = create_processes();
        let message_id = MessageId::new(b"test-message-id");
        let now = Instant::now();

        let mut mp = MockConsensusProcess::new();
        mp.expect_proof_deadline().times(1).returning(move || now);

        let mp_cell = RefCell::new(Some(mp));
        factory
            .expect_create()
            .times(1)
            .returning(move |_, _| Box::new(mp_cell.borrow_mut().take().unwrap()));

        let arc_factory: Arc<dyn ConsensusProcessFactory> = Arc::new(factory);
        let processes = Processes::new(proof_duration, vote_duration, Arc::clone(&arc_factory));

        processes.processes.insert(
            message_id.clone(),
            arc_factory.create(Duration::from_secs(10), Duration::from_secs(20)),
        );

        let result = processes.proof_deadline(&message_id);
        assert!(result.is_ok());
    }

    #[test]
    fn test_vote_deadline() {
        let (mut factory, proof_duration, vote_duration) = create_processes();
        let message_id = MessageId::new(b"test-message-id");
        let now = Instant::now();

        let mut mp = MockConsensusProcess::new();
        mp.expect_vote_deadline().times(1).returning(move || now);

        let mp_cell = RefCell::new(Some(mp));
        factory
            .expect_create()
            .times(1)
            .returning(move |_, _| Box::new(mp_cell.borrow_mut().take().unwrap()));

        let arc_factory: Arc<dyn ConsensusProcessFactory> = Arc::new(factory);
        let processes = Processes::new(proof_duration, vote_duration, Arc::clone(&arc_factory));

        processes.processes.insert(
            message_id.clone(),
            arc_factory.create(Duration::from_secs(10), Duration::from_secs(20)),
        );

        let result = processes.vote_deadline(&message_id);
        assert!(result.is_ok());
    }

    #[test]
    fn test_random() {
        let (mut factory, proof_duration, vote_duration) = create_processes();
        let message_id = MessageId::new(b"test-message-id");
        let random_value = Some([42u8; 32]);

        let mut mp = MockConsensusProcess::new();
        mp.expect_random().times(1).returning(move || random_value);

        let mp_cell = RefCell::new(Some(mp));
        factory
            .expect_create()
            .times(1)
            .returning(move |_, _| Box::new(mp_cell.borrow_mut().take().unwrap()));

        let arc_factory: Arc<dyn ConsensusProcessFactory> = Arc::new(factory);
        let processes = Processes::new(proof_duration, vote_duration, Arc::clone(&arc_factory));

        processes.processes.insert(
            message_id.clone(),
            arc_factory.create(Duration::from_secs(10), Duration::from_secs(20)),
        );

        let result = processes.random(&message_id);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), random_value);
    }

    #[test]
    fn test_update_all_status_none_failed() {
        let (mut factory, proof_duration, vote_duration) = create_processes();
        let message_id = MessageId::new(b"test-message-id");

        let mut mp = MockConsensusProcess::new();
        mp.expect_update_status()
            .times(1)
            .returning(|| ProcessStatus::InProgress);

        let mp_cell = RefCell::new(Some(mp));
        factory
            .expect_create()
            .times(1)
            .returning(move |_, _| Box::new(mp_cell.borrow_mut().take().unwrap()));

        let arc_factory: Arc<dyn ConsensusProcessFactory> = Arc::new(factory);
        let processes = Processes::new(proof_duration, vote_duration, Arc::clone(&arc_factory));

        processes.processes.insert(
            message_id.clone(),
            arc_factory.create(Duration::from_secs(10), Duration::from_secs(20)),
        );

        let failed = processes.update_all_status();
        assert!(failed.is_empty());
        assert!(processes.processes.contains_key(&message_id));
    }

    #[test]
    fn test_update_all_status_some_failed() {
        let (mut factory, proof_duration, vote_duration) = create_processes();
        let message_id = MessageId::new(b"test-message-id");

        let mut mp = MockConsensusProcess::new();
        mp.expect_update_status()
            .times(1)
            .returning(|| ProcessStatus::Failed);

        let mp_cell = RefCell::new(Some(mp));
        factory
            .expect_create()
            .times(1)
            .returning(move |_, _| Box::new(mp_cell.borrow_mut().take().unwrap()));

        let arc_factory: Arc<dyn ConsensusProcessFactory> = Arc::new(factory);
        let processes = Processes::new(proof_duration, vote_duration, Arc::clone(&arc_factory));

        processes.processes.insert(
            message_id.clone(),
            arc_factory.create(Duration::from_secs(10), Duration::from_secs(20)),
        );

        let failed = processes.update_all_status();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0], message_id);
        assert!(!processes.processes.contains_key(&message_id));
    }
}
