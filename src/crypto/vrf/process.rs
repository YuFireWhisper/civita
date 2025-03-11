use std::collections::{HashMap, HashSet};

use libp2p::PeerId;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::time::{Duration, Instant};

use super::config::DEFAULT_THRESHOLD_PERCENTAGE;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Duplicate peer ID: {0}")]
    DuplicatePeerId(PeerId),
    #[error("Duplicate proof")]
    DuplicateProof,
    #[error("Timeout")]
    Timeout,
    #[error("Proof Deadline not yet reached")]
    ProofDeadlineNotReached,
    #[error("Vote Deadline has already been reached")]
    VoteDeadlineReached,
    #[error("Insufficient proofs collected")]
    InsufficientProofs,
    #[error("Peer ID not found")]
    PeerIdNotFound,
}

type ProcessResult<T> = Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq, Copy, Hash)]
pub enum ProcessStatus {
    Completed([u8; 32]),
    InProgress,
    Failed,
}

pub trait ConsensusProcess: Send + Sync {
    fn insert_voter(&mut self, peer_id: PeerId) -> ProcessResult<()>;
    fn insert_proof(&mut self, proof: Vec<u8>) -> ProcessResult<()>;
    fn calculate_consensus(&self) -> ProcessResult<[u8; 32]>;
    fn insert_completion_vote(
        &mut self,
        peer_id: PeerId,
        random: [u8; 32],
    ) -> ProcessResult<Option<[u8; 32]>>;
    fn insert_failure_vote(&mut self, peer_id: PeerId) -> ProcessResult<bool>;
    fn is_proof_timeout(&self) -> bool;
    fn is_vote_timeout(&self) -> bool;
    fn status(&mut self) -> ProcessStatus;
    fn update_status(&mut self) -> ProcessStatus;
    fn proof_deadline(&self) -> &Instant;
    fn vote_deadline(&self) -> &Instant;
    fn random(&self) -> Option<&[u8; 32]>;
}

pub trait ConsensusProcessFactory: Send + Sync {
    fn create(
        &self,
        proof_duration: Duration,
        vote_duration: Duration,
    ) -> Box<dyn ConsensusProcess>;
}

#[derive(Debug, Clone)]
pub struct Process {
    proof_deadline: Instant,
    vote_deadline: Instant,
    voters: HashSet<PeerId>,
    voters_num: usize,
    proofs: Vec<Vec<u8>>,
    votes: HashMap<ProcessStatus, usize>,
    status: ProcessStatus,
}

impl Process {
    fn new(proof_duration: Duration, vote_duration: Duration) -> Self {
        let now = Instant::now();
        let proof_deadline = now + proof_duration;
        let vote_deadline = proof_deadline + vote_duration;
        let voters = HashSet::new();
        let voters_num = 0;
        let proofs = Vec::new();
        let votes = HashMap::new();
        let status = ProcessStatus::InProgress;
        Self {
            proof_deadline,
            vote_deadline,
            voters,
            voters_num,
            proofs,
            votes,
            status,
        }
    }

    fn aggregate_proofs(&self, nums: usize) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for proof in self.proofs.iter().take(nums) {
            hasher.update(proof);
        }
        hasher.finalize().into()
    }

    fn threshold(&self) -> usize {
        (self.voters_num as f64 * DEFAULT_THRESHOLD_PERCENTAGE).ceil() as usize
    }

    fn consensus_status(&self) -> Option<ProcessStatus> {
        if self.status != ProcessStatus::InProgress {
            return Some(self.status);
        }

        if self.voters_num == 0 {
            return None;
        }

        let threshold = self.threshold();
        self.votes
            .iter()
            .find(|(_, &count)| count >= threshold)
            .map(|(&status, _)| status)
    }

    fn insert_status(&mut self, status: ProcessStatus) {
        self.votes
            .entry(status)
            .and_modify(|c| *c += 1)
            .or_insert(1);
    }
}

impl ConsensusProcess for Process {
    fn insert_voter(&mut self, peer_id: PeerId) -> ProcessResult<()> {
        if self.is_proof_timeout() {
            return Err(Error::ProofDeadlineNotReached);
        }

        if self.voters.insert(peer_id) {
            self.voters_num += 1;
            Ok(())
        } else {
            Err(Error::DuplicatePeerId(peer_id))
        }
    }

    fn insert_proof(&mut self, proof: Vec<u8>) -> ProcessResult<()> {
        if self.is_proof_timeout() {
            return Err(Error::ProofDeadlineNotReached);
        }

        if self.proofs.contains(&proof) {
            return Err(Error::DuplicateProof);
        }

        self.proofs.push(proof);
        Ok(())
    }

    fn calculate_consensus(&self) -> ProcessResult<[u8; 32]> {
        if !self.is_proof_timeout() {
            return Err(Error::ProofDeadlineNotReached);
        }

        let threshold = self.threshold();
        if self.proofs.len() < threshold {
            return Err(Error::InsufficientProofs);
        }

        let aggregated = self.aggregate_proofs(threshold);
        Ok(aggregated)
    }

    fn insert_completion_vote(
        &mut self,
        peer_id: PeerId,
        random: [u8; 32],
    ) -> ProcessResult<Option<[u8; 32]>> {
        if !self.is_proof_timeout() {
            return Err(Error::ProofDeadlineNotReached);
        }

        if self.is_vote_timeout() {
            return Err(Error::VoteDeadlineReached);
        }

        if !self.voters.remove(&peer_id) {
            return Err(Error::PeerIdNotFound);
        }

        self.insert_status(ProcessStatus::Completed(random));
        self.update_status();

        if self.status == ProcessStatus::Completed(random) {
            Ok(Some(random))
        } else {
            Ok(None)
        }
    }

    fn insert_failure_vote(&mut self, peer_id: PeerId) -> ProcessResult<bool> {
        if !self.is_proof_timeout() {
            return Err(Error::ProofDeadlineNotReached);
        }

        if self.is_vote_timeout() {
            return Err(Error::VoteDeadlineReached);
        }

        if !self.voters.remove(&peer_id) {
            return Err(Error::PeerIdNotFound);
        }

        self.insert_status(ProcessStatus::Failed);
        self.update_status();

        if self.status == ProcessStatus::Failed {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn is_proof_timeout(&self) -> bool {
        Instant::now() > self.proof_deadline
    }

    fn is_vote_timeout(&self) -> bool {
        Instant::now() > self.vote_deadline
    }

    fn update_status(&mut self) -> ProcessStatus {
        let consensus = self.consensus_status();
        if consensus.is_none() && self.is_vote_timeout() {
            self.status = ProcessStatus::Failed;
        } else if let Some(status) = consensus {
            self.status = status;
        }
        self.status
    }

    fn status(&mut self) -> ProcessStatus {
        self.status
    }

    fn proof_deadline(&self) -> &Instant {
        &self.proof_deadline
    }

    fn vote_deadline(&self) -> &Instant {
        &self.vote_deadline
    }

    fn random(&self) -> Option<&[u8; 32]> {
        match &self.status {
            ProcessStatus::Completed(random) => Some(random),
            _ => None,
        }
    }
}

pub struct ProcessFactory;

impl ConsensusProcessFactory for ProcessFactory {
    fn create(
        &self,
        proof_duration: Duration,
        vote_duration: Duration,
    ) -> Box<dyn ConsensusProcess> {
        Box::new(Process::new(proof_duration, vote_duration))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand;
    use libp2p::PeerId;
    use tokio::time::{sleep, Duration};

    const PROOF_DURATION: Duration = Duration::from_millis(5);
    const VOTE_DURATION: Duration = Duration::from_millis(10);

    const VOTERS_NUM: usize = 10;

    fn generate_peer_id() -> PeerId {
        PeerId::random()
    }

    fn generate_random_proof() -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut proof = vec![0u8; 32];
        rand::Rng::fill(&mut rng, &mut proof[..]);
        proof
    }

    fn create_process() -> Process {
        Process::new(PROOF_DURATION, VOTE_DURATION)
    }

    fn get_threshold() -> usize {
        (VOTERS_NUM as f64 * DEFAULT_THRESHOLD_PERCENTAGE).ceil() as usize
    }

    #[test]
    fn test_new() {
        let duration = Duration::from_secs(5);

        let process = Process::new(duration, duration);

        assert_eq!(process.status, ProcessStatus::InProgress);
        assert_eq!(process.voters.len(), 0);
        assert_eq!(process.voters_num, 0);
        assert_eq!(process.proofs.len(), 0);
        assert_eq!(process.votes.len(), 0);
        assert!(process.proof_deadline > Instant::now());
    }

    #[test]
    fn test_aggregate_proofs() {
        const TEST_PROOF_1: [u8; 4] = [1, 2, 3, 4];
        const TEST_PROOF_2: [u8; 4] = [5, 6, 7, 8];

        let mut process = create_process();
        process.proofs.push(TEST_PROOF_1.to_vec());
        process.proofs.push(TEST_PROOF_2.to_vec());

        let hash = process.aggregate_proofs(2);

        let mut hasher = Sha256::new();
        hasher.update(TEST_PROOF_1);
        hasher.update(TEST_PROOF_2);
        let expected: [u8; 32] = hasher.finalize().into();

        assert_eq!(hash, expected);
    }

    #[test]
    fn test_threshold() {
        let mut process = create_process();
        process.voters_num = VOTERS_NUM;

        let threshold = process.threshold();

        let expected = get_threshold();
        assert_eq!(threshold, expected);
    }

    #[test]
    fn test_consensus_status_empty() {
        let process = create_process();

        let status = process.consensus_status();

        assert_eq!(status, None);
    }

    #[test]
    fn test_consensus_status_has_consensus() {
        let mut process = create_process();
        let threshold = get_threshold();
        process.voters_num = VOTERS_NUM;
        process.votes.insert(ProcessStatus::Failed, threshold);

        let status = process.consensus_status();

        assert_eq!(status, Some(ProcessStatus::Failed));
    }

    #[test]
    fn test_consensus_status_already_completed() {
        let random = [1u8; 32];
        let mut process = create_process();
        process.status = ProcessStatus::Completed(random);

        let status = process.consensus_status();

        assert_eq!(status, Some(ProcessStatus::Completed(random)));
    }

    #[test]
    fn test_insert_status() {
        let mut process = create_process();
        let status = ProcessStatus::Failed;

        process.insert_status(status);
        process.insert_status(status);

        assert_eq!(process.votes.get(&status), Some(&2));
    }

    #[test]
    fn test_insert_voter_success() {
        let mut process = create_process();
        let peer_id = generate_peer_id();

        let result = process.insert_voter(peer_id);

        assert!(result.is_ok());
        assert_eq!(process.voters_num, 1);
        assert!(process.voters.contains(&peer_id));
    }

    #[test]
    fn test_insert_voter_duplicate() {
        let mut process = create_process();
        let peer_id = generate_peer_id();
        process.insert_voter(peer_id).unwrap();

        let result = process.insert_voter(peer_id);

        assert!(matches!(result, Err(Error::DuplicatePeerId(_))));
        assert_eq!(process.voters_num, 1);
    }

    #[tokio::test]
    async fn test_insert_voter_timeout() {
        let mut process = create_process();
        let peer_id = generate_peer_id();
        sleep(PROOF_DURATION + VOTE_DURATION).await;

        let result = process.insert_voter(peer_id);

        assert!(matches!(result, Err(Error::ProofDeadlineNotReached)));
    }

    #[test]
    fn test_insert_proof_success() {
        let mut process = create_process();
        let proof = generate_random_proof();

        let result = process.insert_proof(proof.clone());

        assert!(result.is_ok());
        assert!(process.proofs.contains(&proof));
    }

    #[test]
    fn test_insert_proof_duplicate() {
        let mut process = create_process();
        let proof = generate_random_proof();
        process.insert_proof(proof.clone()).unwrap();

        let result = process.insert_proof(proof);

        assert!(matches!(result, Err(Error::DuplicateProof)));
    }

    #[tokio::test]
    async fn test_insert_proof_timeout() {
        let mut process = create_process();
        let proof = generate_random_proof();
        sleep(PROOF_DURATION).await;

        let result = process.insert_proof(proof);

        assert!(matches!(result, Err(Error::ProofDeadlineNotReached)));
    }

    #[test]
    fn test_calculate_consensus_deadline_not_reached() {
        let process = create_process();
        let result = process.calculate_consensus();
        assert!(matches!(result, Err(Error::ProofDeadlineNotReached)));
    }

    #[tokio::test]
    async fn test_calculate_consensus_insufficient_proofs() {
        let mut process = create_process();
        process.voters_num = VOTERS_NUM;
        sleep(PROOF_DURATION).await;

        let result = process.calculate_consensus();

        assert!(matches!(result, Err(Error::InsufficientProofs)));
    }

    #[tokio::test]
    async fn test_calculate_consensus_success() {
        let mut process = create_process();
        process.voters_num = VOTERS_NUM;
        let threshold = get_threshold();

        for _ in 0..threshold {
            process.proofs.push(generate_random_proof());
        }

        sleep(PROOF_DURATION).await;

        let result = process.calculate_consensus();

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), process.aggregate_proofs(threshold));
    }

    #[test]
    fn test_insert_completion_vote_deadline_not_reached() {
        let mut process = create_process();
        let peer_id = generate_peer_id();
        let random = [1u8; 32];
        process.insert_voter(peer_id).unwrap();

        let result = process.insert_completion_vote(peer_id, random);

        assert!(matches!(result, Err(Error::ProofDeadlineNotReached)));
    }

    #[tokio::test]
    async fn test_insert_completion_vote_peer_not_found() {
        let mut process = create_process();
        let peer_id = generate_peer_id();
        let random = [1u8; 32];
        sleep(PROOF_DURATION).await;

        let result = process.insert_completion_vote(peer_id, random);

        assert!(matches!(result, Err(Error::PeerIdNotFound)));
    }

    #[tokio::test]
    async fn test_insert_completion_vote_success_without_consensus() {
        let mut process = create_process();
        let peer_id = generate_peer_id();
        let random = [1u8; 32];
        process.insert_voter(peer_id).unwrap();
        process.voters_num = VOTERS_NUM; // Set a higher voter count so we don't reach consensus
        sleep(PROOF_DURATION).await;

        let result = process.insert_completion_vote(peer_id, random);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
        assert!(!process.voters.contains(&peer_id));
        assert_eq!(
            process.votes.get(&ProcessStatus::Completed(random)),
            Some(&1)
        );
    }

    #[tokio::test]
    async fn test_insert_completion_vote_success_with_consensus() {
        let mut process = create_process();
        let peer_id = generate_peer_id();
        let random = [1u8; 32];
        process.insert_voter(peer_id).unwrap();
        println!("Voters: {:?}", process.voters);
        println!("Voters num: {:?}", process.voters_num);
        // Only one voter means we'll reach consensus immediately
        sleep(PROOF_DURATION).await;

        let result = process.insert_completion_vote(peer_id, random);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some(random));
        assert!(!process.voters.contains(&peer_id));
        assert_eq!(process.status, ProcessStatus::Completed(random));
    }

    #[test]
    fn test_insert_failure_vote_deadline_not_reached() {
        let mut process = create_process();
        let peer_id = generate_peer_id();
        process.insert_voter(peer_id).unwrap();

        let result = process.insert_failure_vote(peer_id);

        assert!(matches!(result, Err(Error::ProofDeadlineNotReached)));
    }

    #[tokio::test]
    async fn test_insert_failure_vote_peer_not_found() {
        let mut process = create_process();
        let peer_id = generate_peer_id();
        sleep(PROOF_DURATION).await;

        let result = process.insert_failure_vote(peer_id);

        assert!(matches!(result, Err(Error::PeerIdNotFound)));
    }

    #[tokio::test]
    async fn test_insert_failure_vote_success_without_consensus() {
        let mut process = create_process();
        let peer_id = generate_peer_id();
        process.insert_voter(peer_id).unwrap();
        process.voters_num = VOTERS_NUM; // Set a higher voter count so we don't reach consensus
        sleep(PROOF_DURATION).await;

        let result = process.insert_failure_vote(peer_id);

        assert!(result.is_ok());
        assert!(!result.unwrap());
        assert!(!process.voters.contains(&peer_id));
        assert_eq!(process.votes.get(&ProcessStatus::Failed), Some(&1));
    }

    #[tokio::test]
    async fn test_insert_failure_vote_success_with_consensus() {
        let mut process = create_process();
        let peer_id = generate_peer_id();
        process.insert_voter(peer_id).unwrap();
        // Only one voter means we'll reach consensus immediately
        sleep(PROOF_DURATION).await;

        let result = process.insert_failure_vote(peer_id);

        assert!(result.is_ok());
        assert!(result.unwrap());
        assert!(!process.voters.contains(&peer_id));
        assert_eq!(process.status, ProcessStatus::Failed);
    }

    #[tokio::test]
    async fn test_is_proof_timeout() {
        let process = create_process();

        let before_timeout = process.is_proof_timeout();
        sleep(PROOF_DURATION).await;
        let after_timeout = process.is_proof_timeout();

        assert!(!before_timeout);
        assert!(after_timeout);
    }

    #[tokio::test]
    async fn test_is_vote_timeout() {
        let process = create_process();

        let before_timeout = process.is_vote_timeout();
        sleep(PROOF_DURATION + VOTE_DURATION).await;
        let after_timeout = process.is_vote_timeout();

        assert!(!before_timeout);
        assert!(after_timeout);
    }

    #[test]
    fn test_status() {
        let mut process = create_process();
        let initial_status = process.status;
        let random = [1u8; 32];
        process.status = ProcessStatus::Completed(random);

        let status = process.status();

        assert_eq!(initial_status, ProcessStatus::InProgress);
        assert_eq!(status, ProcessStatus::Completed(random));
    }

    #[tokio::test]
    async fn test_update_status_timeout() {
        let mut process = create_process();
        sleep(PROOF_DURATION + VOTE_DURATION).await;

        let status = process.update_status();

        assert_eq!(status, ProcessStatus::Failed);
        assert_eq!(process.status, ProcessStatus::Failed);
    }

    #[test]
    fn test_update_status_consensus() {
        let mut process = create_process();
        let threshold = get_threshold();
        process.voters_num = VOTERS_NUM;
        process.votes.insert(ProcessStatus::Failed, threshold);

        let status = process.update_status();

        assert_eq!(status, ProcessStatus::Failed);
        assert_eq!(process.status, ProcessStatus::Failed);
    }

    #[test]
    fn test_update_status_no_change() {
        let mut process = create_process();
        let status = process.update_status();
        assert_eq!(status, ProcessStatus::InProgress);
        assert_eq!(process.status, ProcessStatus::InProgress);
    }

    #[test]
    fn test_deadline() {
        let process = create_process();
        let expected_deadline = process.proof_deadline;
        let deadline = process.proof_deadline();
        assert_eq!(*deadline, expected_deadline);
    }

    #[test]
    fn test_random_none() {
        let process = create_process();
        let random = process.random();
        assert_eq!(random, None);
    }

    #[test]
    fn test_random_some() {
        let mut process = create_process();
        let random_value = [1u8; 32];
        process.status = ProcessStatus::Completed(random_value);

        let random = process.random();

        assert_eq!(random, Some(&random_value));
    }

    #[test]
    fn test_create() {
        let factory = ProcessFactory;

        let mut process = factory.create(PROOF_DURATION, VOTE_DURATION);

        assert_eq!(process.status(), ProcessStatus::InProgress);
        assert!(process.proof_deadline() > &Instant::now());
    }
}
