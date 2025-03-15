use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap, HashSet},
};

use libp2p::PeerId;
use sha2::{Digest, Sha256};
use tokio::time::{Duration, Instant};

use crate::crypto::vrf::dvrf::config::DEFAULT_THRESHOLD_PERCENTAGE;

use super::{ConsensusProcess, ConsensusProcessFactory, Error, ProcessStatus};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone)]
pub struct Process {
    proof_deadline: Instant,
    vote_deadline: Instant,
    voters: HashSet<PeerId>,
    already_voted: HashSet<PeerId>,
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
        let already_voted = HashSet::new();
        let proofs = Vec::new();
        let votes = HashMap::new();
        let status = ProcessStatus::InProgress;
        Self {
            proof_deadline,
            vote_deadline,
            voters,
            already_voted,
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
        if self.voters.is_empty() {
            return 0;
        }
        (self.voters.len() as f64 * DEFAULT_THRESHOLD_PERCENTAGE).ceil() as usize
    }

    fn consensus_status(&self) -> Option<ProcessStatus> {
        if self.status != ProcessStatus::InProgress {
            return Some(self.status);
        }

        if self.already_voted.is_empty() {
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
    fn insert_voter(&mut self, peer_id: PeerId) -> Result<()> {
        if self.is_proof_timeout() {
            return Err(Error::ProofDeadlineReached);
        }

        if self.voters.insert(peer_id) {
            Ok(())
        } else {
            Err(Error::DuplicatePeerId(peer_id))
        }
    }

    fn insert_proof(&mut self, proof: Vec<u8>) -> Result<()> {
        if self.is_proof_timeout() {
            return Err(Error::ProofDeadlineReached);
        }

        if self.proofs.contains(&proof) {
            return Err(Error::DuplicateProof);
        }

        self.proofs.push(proof);
        Ok(())
    }

    fn calculate_consensus(&self) -> Result<[u8; 32]> {
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
    ) -> Result<Option<[u8; 32]>> {
        if !self.is_proof_timeout() {
            return Err(Error::ProofDeadlineNotReached);
        }

        if self.is_vote_timeout() {
            return Err(Error::VoteDeadlineReached);
        }

        if !self.voters.contains(&peer_id) {
            return Err(Error::PeerIdNotFound(peer_id));
        }

        if !self.already_voted.insert(peer_id) {
            return Err(Error::PeerIdAlreadyVoted(peer_id));
        }

        self.insert_status(ProcessStatus::Completed(random));
        self.update_status();

        if self.status == ProcessStatus::Completed(random) {
            Ok(Some(random))
        } else {
            Ok(None)
        }
    }

    fn insert_failure_vote(&mut self, peer_id: PeerId) -> Result<bool> {
        if !self.is_proof_timeout() {
            return Err(Error::ProofDeadlineNotReached);
        }

        if self.is_vote_timeout() {
            return Err(Error::VoteDeadlineReached);
        }

        if !self.voters.contains(&peer_id) {
            return Err(Error::PeerIdNotFound(peer_id));
        }

        if !self.already_voted.insert(peer_id) {
            return Err(Error::PeerIdAlreadyVoted(peer_id));
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
        Instant::now() >= self.proof_deadline
    }

    fn is_vote_timeout(&self) -> bool {
        Instant::now() >= self.vote_deadline
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

    fn status(&self) -> ProcessStatus {
        self.status
    }

    fn proof_deadline(&self) -> Instant {
        self.proof_deadline
    }

    fn vote_deadline(&self) -> Instant {
        self.vote_deadline
    }

    fn random(&self) -> Option<[u8; 32]> {
        match &self.status {
            ProcessStatus::Completed(random) => Some(*random),
            _ => None,
        }
    }

    fn elect(&self, num: usize) -> Result<Vec<PeerId>> {
        let seed = self.random().unwrap(); // We will chage this line later

        let mut heap = BinaryHeap::with_capacity(num + 1);

        for &peer_id in self.voters.iter() {
            let mut hasher = Sha256::new();
            hasher.update(seed);
            hasher.update(peer_id.to_bytes());
            let hash = hasher.finalize();
            let score = u64::from_le_bytes(hash[..8].try_into().unwrap());

            heap.push(Reverse((score, peer_id)));
            if heap.len() > num {
                heap.pop();
            }
        }

        let mut result: Vec<_> = heap
            .into_iter()
            .map(|Reverse((_, peer_id))| peer_id)
            .collect();
        result.sort();

        Ok(result)
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
    const ELECTED_NUM: usize = 5;

    fn generate_random_peer_id() -> PeerId {
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

    fn insert_random_voters(process: &mut Process, num: usize) {
        let mut used_peer_ids = HashSet::new();
        for _ in 0..num {
            let mut peer_id = generate_random_peer_id();
            while used_peer_ids.contains(&peer_id) {
                peer_id = generate_random_peer_id();
            }
            used_peer_ids.insert(peer_id);
            process.insert_voter(peer_id).unwrap();
        }
    }

    fn insert_random_completion_votes(
        process: &mut Process,
        num: usize,
    ) -> Result<Option<[u8; 32]>> {
        let required_voters = std::cmp::max(num, process.voters.len());
        for _ in process.voters.len()..required_voters {
            let peer_id = generate_random_peer_id();
            process.insert_voter(peer_id)?;
        }
        let peer_ids: Vec<PeerId> = process.voters.iter().cloned().collect();
        let random = [1u8; 32];
        for i in 0..num {
            if i >= peer_ids.len() {
                return Err(Error::InsufficientProofs);
            }
            let peer_id = peer_ids[i];
            let result = process.insert_completion_vote(peer_id, random)?;
            if result.is_some() {
                return Ok(result);
            }
        }
        process.update_status();
        Ok(process.random())
    }

    fn insert_random_failure_votes(process: &mut Process, num: usize) -> Result<bool> {
        let required_voters = std::cmp::max(num, process.voters.len());
        for _ in process.voters.len()..required_voters {
            let peer_id = generate_random_peer_id();
            process.insert_voter(peer_id)?;
        }
        let peer_ids: Vec<PeerId> = process.voters.iter().cloned().collect();
        for i in 0..num {
            if i >= peer_ids.len() {
                return Err(Error::InsufficientProofs);
            }
            let peer_id = peer_ids[i];
            process.insert_failure_vote(peer_id)?;
        }
        process.update_status();
        Ok(process.status == ProcessStatus::Failed)
    }

    fn calculate_threshold(num: usize, percentage: f64) -> usize {
        (num as f64 * percentage).ceil() as usize
    }

    #[test]
    fn test_new() {
        let duration = Duration::from_secs(5);
        let process = Process::new(duration, duration);
        assert_eq!(process.status, ProcessStatus::InProgress);
        assert_eq!(process.voters.len(), 0);
        assert_eq!(process.already_voted.len(), 0);
        assert_eq!(process.proofs.len(), 0);
        assert_eq!(process.votes.len(), 0);
        assert!(process.proof_deadline > Instant::now());
    }

    #[test]
    fn test_consensus_status_no_votes() {
        let process = create_process();
        let status = process.consensus_status();
        assert_eq!(status, None);
    }

    #[test]
    fn test_insert_voter_success() {
        let mut process = create_process();
        let peer_id = generate_random_peer_id();
        let result = process.insert_voter(peer_id);
        assert!(result.is_ok());
        assert_eq!(process.voters.len(), 1);
        assert!(process.voters.contains(&peer_id));
    }

    #[test]
    fn test_insert_voter_duplicate() {
        let mut process = create_process();
        let peer_id = generate_random_peer_id();
        process.insert_voter(peer_id).unwrap();
        let result = process.insert_voter(peer_id);
        assert!(matches!(result, Err(Error::DuplicatePeerId(_))));
        assert_eq!(process.voters.len(), 1);
    }

    #[tokio::test]
    async fn test_insert_voter_timeout() {
        let mut process = create_process();
        let peer_id = generate_random_peer_id();
        sleep(PROOF_DURATION).await;
        let result = process.insert_voter(peer_id);
        assert!(matches!(result, Err(Error::ProofDeadlineReached)));
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
        assert!(matches!(result, Err(Error::ProofDeadlineReached)));
    }

    #[tokio::test]
    async fn test_calculate_consensus_success() {
        let mut process = create_process();
        let threshold = calculate_threshold(VOTERS_NUM, DEFAULT_THRESHOLD_PERCENTAGE);
        insert_random_voters(&mut process, VOTERS_NUM);
        for i in 0..threshold {
            let proof = vec![i as u8; 32];
            process.insert_proof(proof).unwrap();
        }
        sleep(PROOF_DURATION).await;
        let result = process.calculate_consensus();
        assert!(result.is_ok());
        let mut hasher = Sha256::new();
        for i in 0..threshold {
            hasher.update(vec![i as u8; 32]);
        }
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(result.unwrap(), expected);
    }

    #[test]
    fn test_calculate_consensus_before_deadline() {
        let process = create_process();
        let result = process.calculate_consensus();
        assert!(matches!(result, Err(Error::ProofDeadlineNotReached)));
    }

    #[tokio::test]
    async fn test_calculate_consensus_insufficient_proofs() {
        let mut process = create_process();
        let threshold = calculate_threshold(VOTERS_NUM, DEFAULT_THRESHOLD_PERCENTAGE);
        insert_random_voters(&mut process, VOTERS_NUM);
        for i in 0..threshold - 1 {
            let proof = vec![i as u8; 32];
            process.insert_proof(proof).unwrap();
        }
        sleep(PROOF_DURATION).await;
        let result = process.calculate_consensus();
        assert!(matches!(result, Err(Error::InsufficientProofs)));
    }

    #[tokio::test]
    async fn test_insert_completion_vote_success() {
        let mut process = create_process();
        let peer_id = generate_random_peer_id();
        let random = [1u8; 32];
        process.insert_voter(peer_id).unwrap();
        sleep(PROOF_DURATION).await;
        let result = process.insert_completion_vote(peer_id, random);
        assert!(result.is_ok());
        assert!(process.already_voted.contains(&peer_id));
        assert!(process
            .votes
            .contains_key(&ProcessStatus::Completed(random)));
        assert_eq!(
            process.votes.get(&ProcessStatus::Completed(random)),
            Some(&1)
        );
    }

    #[tokio::test]
    async fn test_insert_completion_vote_after_vote_deadline() {
        let mut process = create_process();
        let peer_id = generate_random_peer_id();
        process.insert_voter(peer_id).unwrap();
        sleep(PROOF_DURATION + VOTE_DURATION + Duration::from_millis(5)).await;
        let random = [1u8; 32];
        let result = process.insert_completion_vote(peer_id, random);
        assert!(matches!(result, Err(Error::VoteDeadlineReached)));
    }

    #[test]
    fn test_insert_completion_vote_before_proof_deadline() {
        let mut process = create_process();
        let peer_id = generate_random_peer_id();
        process.insert_voter(peer_id).unwrap();
        let random = [1u8; 32];
        let result = process.insert_completion_vote(peer_id, random);
        assert!(matches!(result, Err(Error::ProofDeadlineNotReached)));
    }

    #[tokio::test]
    async fn test_insert_completion_vote_unknown_peer() {
        let mut process = create_process();
        let peer_id = generate_random_peer_id();
        let random = [1u8; 32];
        sleep(PROOF_DURATION).await;
        let result = process.insert_completion_vote(peer_id, random);
        assert!(matches!(result, Err(Error::PeerIdNotFound(_))));
    }

    #[tokio::test]
    async fn test_insert_completion_vote_reach_consensus() {
        let mut process = create_process();
        let threshold = calculate_threshold(VOTERS_NUM, DEFAULT_THRESHOLD_PERCENTAGE);
        insert_random_voters(&mut process, VOTERS_NUM);
        sleep(PROOF_DURATION).await;
        let result = insert_random_completion_votes(&mut process, threshold);
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_insert_completion_vote_not_reach_consensus() {
        let mut process = create_process();
        let threshold = calculate_threshold(VOTERS_NUM, DEFAULT_THRESHOLD_PERCENTAGE);
        insert_random_voters(&mut process, VOTERS_NUM);
        sleep(PROOF_DURATION).await;
        let result = insert_random_completion_votes(&mut process, threshold - 1);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
    }

    #[tokio::test]
    async fn test_insert_failure_vote_success() {
        let mut process = create_process();
        insert_random_voters(&mut process, VOTERS_NUM);
        sleep(PROOF_DURATION).await;
        let result = insert_random_failure_votes(&mut process, VOTERS_NUM);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_insert_failure_vote_after_vote_deadline() {
        let mut process = create_process();
        let peer_id = generate_random_peer_id();
        process.insert_voter(peer_id).unwrap();
        sleep(PROOF_DURATION + VOTE_DURATION + Duration::from_millis(5)).await;
        let result = process.insert_failure_vote(peer_id);
        assert!(matches!(result, Err(Error::VoteDeadlineReached)));
    }

    #[test]
    fn test_insert_failure_vote_before_proof_deadline() {
        let mut process = create_process();
        insert_random_voters(&mut process, VOTERS_NUM);
        let result = insert_random_failure_votes(&mut process, 1);
        assert!(matches!(result, Err(Error::ProofDeadlineNotReached)));
    }

    #[tokio::test]
    async fn test_insert_failure_vote_unknown_peer() {
        let mut process = create_process();
        let peer_id = generate_random_peer_id();
        sleep(PROOF_DURATION).await;
        let result = process.insert_failure_vote(peer_id);
        assert!(matches!(result, Err(Error::PeerIdNotFound(_))));
    }

    #[tokio::test]
    async fn test_insert_failure_vote_reach_consensus() {
        let mut process = create_process();
        let threshold = calculate_threshold(VOTERS_NUM, DEFAULT_THRESHOLD_PERCENTAGE);
        insert_random_voters(&mut process, VOTERS_NUM);
        sleep(PROOF_DURATION).await;
        let result = insert_random_failure_votes(&mut process, threshold);
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert_eq!(process.status, ProcessStatus::Failed);
    }

    #[tokio::test]
    async fn test_insert_failure_vote_not_reach_consensus() {
        let mut process = create_process();
        let threshold = calculate_threshold(VOTERS_NUM, DEFAULT_THRESHOLD_PERCENTAGE);
        insert_random_voters(&mut process, VOTERS_NUM);
        sleep(PROOF_DURATION).await;
        let result = insert_random_failure_votes(&mut process, threshold - 1);
        assert!(result.is_ok());
        assert!(!result.unwrap());
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

    #[tokio::test]
    async fn test_update_status_consensus() {
        let mut process = create_process();
        let threshold = calculate_threshold(VOTERS_NUM, DEFAULT_THRESHOLD_PERCENTAGE);
        let mut peer_ids = Vec::new();
        for _ in 0..VOTERS_NUM {
            let peer_id = generate_random_peer_id();
            process.insert_voter(peer_id).unwrap();
            peer_ids.push(peer_id);
        }
        sleep(PROOF_DURATION).await;
        let random = [1u8; 32];
        for peer_id in peer_ids.iter().take(threshold) {
            process.insert_completion_vote(*peer_id, random).unwrap();
        }
        let status = process.update_status();
        assert!(matches!(status, ProcessStatus::Completed(_)));
    }

    #[test]
    fn test_update_status_no_change() {
        let mut process = create_process();
        let status = process.update_status();
        assert_eq!(status, ProcessStatus::InProgress);
        assert_eq!(process.status, ProcessStatus::InProgress);
    }

    #[test]
    fn test_proof_deadline() {
        let process = create_process();
        let expected_deadline = process.proof_deadline;
        let deadline = process.proof_deadline();
        assert_eq!(deadline, expected_deadline);
    }

    #[test]
    fn test_vote_deadline() {
        let process = create_process();
        let expected_deadline = process.proof_deadline + VOTE_DURATION;
        let deadline = process.vote_deadline();
        assert_eq!(deadline, expected_deadline);
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
        assert_eq!(random, Some(random_value));
    }

    #[test]
    fn test_create() {
        let factory = ProcessFactory;
        let process = factory.create(PROOF_DURATION, VOTE_DURATION);
        assert_eq!(process.status(), ProcessStatus::InProgress);
        assert!(process.proof_deadline() > Instant::now());
    }

    #[tokio::test]
    async fn test_elect_success() {
        let mut process = create_process();
        let threshold = calculate_threshold(VOTERS_NUM, DEFAULT_THRESHOLD_PERCENTAGE);
        let mut peer_ids = Vec::new();
        for _ in 0..VOTERS_NUM {
            let peer_id = generate_random_peer_id();
            process.insert_voter(peer_id).unwrap();
            peer_ids.push(peer_id);
        }
        sleep(PROOF_DURATION).await;
        for peer_id in peer_ids.iter().take(threshold) {
            process.insert_completion_vote(*peer_id, [1u8; 32]).unwrap();
        }

        let elected = process.elect(ELECTED_NUM).unwrap();

        assert_eq!(elected.len(), ELECTED_NUM);
        for peer_id in elected.iter() {
            assert!(peer_ids.contains(peer_id));
        }
    }
}
