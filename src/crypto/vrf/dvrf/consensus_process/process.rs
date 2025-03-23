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

    fn insert_output(&mut self, output: Vec<u8>) -> Result<()> {
        if self.is_proof_timeout() {
            return Err(Error::ProofDeadlineReached);
        }

        if self.proofs.contains(&output) {
            return Err(Error::DuplicateProof);
        }

        self.proofs.push(output);
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
        if self.voters.len() < num {
            return Err(Error::InsufficientVoters);
        }

        if !self.is_proof_timeout() {
            return Err(Error::ProofDeadlineNotReached);
        }

        if self.is_vote_timeout() {
            return Err(Error::ProofDeadlineReached);
        }

        let seed = self.random().ok_or(Error::ProcessNotCompleted)?;
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
    use libp2p::PeerId;
    use tokio::time::{sleep, Duration};

    const PROOF_DURATION: Duration = Duration::from_millis(5);
    const VOTE_DURATION: Duration = Duration::from_millis(10);
    const VOTERS_NUM: usize = 10;
    const ELECTED_NUM: usize = 5;
    const RANDOM: [u8; 32] = [1u8; 32];

    struct TestContext {
        process: Process,
        peer_ids: Vec<PeerId>,
    }

    impl TestContext {
        fn new() -> Self {
            let process = Process::new(PROOF_DURATION, VOTE_DURATION);
            let peer_ids = Vec::new();
            Self { process, peer_ids }
        }

        fn with_voters(mut self, num: usize) -> Self {
            while self.peer_ids.len() < num {
                let peer_id = generate_random_peer_id();
                if self.process.insert_voter(peer_id).is_ok() {
                    self.peer_ids.push(peer_id);
                }
                // Ignore duplicate peer IDs
            }
            self
        }

        async fn after_proof_deadline(self) -> Self {
            sleep(PROOF_DURATION).await;
            self
        }

        async fn after_vote_deadline(self) -> Self {
            sleep(PROOF_DURATION + VOTE_DURATION).await;
            self
        }

        fn insert_outputs(&mut self, num: usize) -> Result<()> {
            for i in 0..num {
                let proof = vec![i as u8; 32];
                self.process.insert_output(proof)?;
            }
            Ok(())
        }

        fn insert_completion_votes(
            &mut self,
            num: usize,
            random: [u8; 32],
        ) -> Result<Option<[u8; 32]>> {
            for i in 0..num {
                let peer_id = self.peer_ids[i];
                let result = self.process.insert_completion_vote(peer_id, random)?;
                if result.is_some() {
                    return Ok(result);
                }
            }
            self.process.update_status();
            Ok(self.process.random())
        }

        fn insert_failure_votes(&mut self, num: usize) -> Result<bool> {
            for i in 0..num {
                let peer_id = self.peer_ids[i];
                self.process.insert_failure_vote(peer_id)?;
            }
            self.process.update_status();
            Ok(self.process.status == ProcessStatus::Failed)
        }
    }

    fn generate_random_peer_id() -> PeerId {
        PeerId::random()
    }

    fn generate_random_output() -> Vec<u8> {
        let mut rng = rand::rng();
        let mut proof = vec![0u8; 32];
        rand::Rng::fill(&mut rng, &mut proof[..]);
        proof
    }

    fn calculate_threshold(num: usize, percentage: f64) -> usize {
        (num as f64 * percentage).ceil() as usize
    }

    #[test]
    fn test_new() {
        let process = Process::new(PROOF_DURATION, VOTE_DURATION);

        assert_eq!(process.status, ProcessStatus::InProgress);
        assert_eq!(process.voters.len(), 0);
        assert_eq!(process.already_voted.len(), 0);
        assert_eq!(process.proofs.len(), 0);
        assert_eq!(process.votes.len(), 0);
        assert!(process.proof_deadline > Instant::now());
    }

    #[test]
    fn test_consensus_status_no_votes() {
        let ctx = TestContext::new();

        let result = ctx.process.consensus_status();

        assert_eq!(result, None);
    }

    #[test]
    fn test_insert_voter_success() {
        let mut ctx = TestContext::new();
        let peer_id = generate_random_peer_id();

        let result = ctx.process.insert_voter(peer_id);

        assert!(result.is_ok());
        assert!(ctx.process.voters.contains(&peer_id));
        assert_eq!(ctx.process.voters.len(), 1);
    }

    #[test]
    fn test_insert_voter_duplicate() {
        let mut ctx = TestContext::new();
        let peer_id = generate_random_peer_id();

        ctx.process.insert_voter(peer_id).unwrap();
        let result = ctx.process.insert_voter(peer_id);

        assert!(matches!(result, Err(Error::DuplicatePeerId(_))));
        assert_eq!(ctx.process.voters.len(), 1);
    }

    #[tokio::test]
    async fn test_insert_voter_timeout() {
        let mut ctx = TestContext::new().after_proof_deadline().await;
        let peer_id = generate_random_peer_id();

        let result = ctx.process.insert_voter(peer_id);

        assert!(matches!(result, Err(Error::ProofDeadlineReached)));
    }

    #[test]
    fn test_insert_output_success() {
        let mut ctx = TestContext::new();
        let proof = generate_random_output();

        let result = ctx.process.insert_output(proof.clone());

        assert!(result.is_ok());
        assert!(ctx.process.proofs.contains(&proof));
        assert_eq!(ctx.process.proofs.len(), 1);
    }

    #[test]
    fn test_insert_output_duplicate() {
        let mut ctx = TestContext::new();
        let proof = generate_random_output();

        ctx.process.insert_output(proof.clone()).unwrap();
        let result = ctx.process.insert_output(proof);

        assert!(matches!(result, Err(Error::DuplicateProof)));
        assert_eq!(ctx.process.proofs.len(), 1);
    }

    #[tokio::test]
    async fn test_insert_output_timeout() {
        let mut ctx = TestContext::new().after_proof_deadline().await;
        let proof = generate_random_output();

        let result = ctx.process.insert_output(proof);

        assert!(matches!(result, Err(Error::ProofDeadlineReached)));
    }

    #[tokio::test]
    async fn test_calculate_consensus_success() {
        let mut ctx = TestContext::new().with_voters(VOTERS_NUM);
        let threshold = calculate_threshold(VOTERS_NUM, DEFAULT_THRESHOLD_PERCENTAGE);

        ctx.insert_outputs(threshold).unwrap();
        let ctx = ctx.after_proof_deadline().await;

        let result = ctx.process.calculate_consensus();

        assert!(result.is_ok());
        // We don't to check the actual value of the consensus
    }

    #[test]
    fn test_calculate_consensus_before_deadline() {
        let ctx = TestContext::new();

        let result = ctx.process.calculate_consensus();

        assert!(matches!(result, Err(Error::ProofDeadlineNotReached)));
    }

    #[tokio::test]
    async fn test_calculate_consensus_insufficient_proofs() {
        let mut ctx = TestContext::new().with_voters(VOTERS_NUM);
        let threshold = calculate_threshold(VOTERS_NUM, DEFAULT_THRESHOLD_PERCENTAGE);

        ctx.insert_outputs(threshold - 1).unwrap();
        let ctx = ctx.after_proof_deadline().await;

        let result = ctx.process.calculate_consensus();

        assert!(matches!(result, Err(Error::InsufficientProofs)));
    }

    #[tokio::test]
    async fn test_insert_completion_vote_success() {
        let mut ctx = TestContext::new();
        let peer_id = generate_random_peer_id();

        ctx.process.insert_voter(peer_id).unwrap();
        let mut ctx = ctx.after_proof_deadline().await;

        let result = ctx.process.insert_completion_vote(peer_id, RANDOM);

        assert!(result.is_ok());
        assert!(ctx.process.already_voted.contains(&peer_id));
        assert!(ctx
            .process
            .votes
            .contains_key(&ProcessStatus::Completed(RANDOM)));
        assert_eq!(
            ctx.process.votes.get(&ProcessStatus::Completed(RANDOM)),
            Some(&1)
        );
    }

    #[tokio::test]
    async fn test_insert_completion_vote_after_vote_deadline() {
        let mut ctx = TestContext::new();
        let peer_id = generate_random_peer_id();

        ctx.process.insert_voter(peer_id).unwrap();
        let mut ctx = ctx.after_vote_deadline().await;

        let result = ctx.process.insert_completion_vote(peer_id, RANDOM);

        assert!(matches!(result, Err(Error::VoteDeadlineReached)));
    }

    #[test]
    fn test_insert_completion_vote_before_proof_deadline() {
        let mut ctx = TestContext::new();
        let peer_id = generate_random_peer_id();

        ctx.process.insert_voter(peer_id).unwrap();
        let result = ctx.process.insert_completion_vote(peer_id, RANDOM);

        assert!(matches!(result, Err(Error::ProofDeadlineNotReached)));
    }

    #[tokio::test]
    async fn test_insert_completion_vote_unknown_peer() {
        let mut ctx = TestContext::new().after_proof_deadline().await;
        let peer_id = generate_random_peer_id();

        let result = ctx.process.insert_completion_vote(peer_id, RANDOM);

        assert!(matches!(result, Err(Error::PeerIdNotFound(_))));
    }

    #[tokio::test]
    async fn test_insert_completion_vote_reach_consensus() {
        let mut ctx = TestContext::new()
            .with_voters(VOTERS_NUM)
            .after_proof_deadline()
            .await;
        let threshold = calculate_threshold(VOTERS_NUM, DEFAULT_THRESHOLD_PERCENTAGE);

        let result = ctx.insert_completion_votes(threshold, RANDOM);

        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
        assert_eq!(ctx.process.status, ProcessStatus::Completed(RANDOM));
    }

    #[tokio::test]
    async fn test_insert_completion_vote_not_reach_consensus() {
        let mut ctx = TestContext::new()
            .with_voters(VOTERS_NUM)
            .after_proof_deadline()
            .await;
        let threshold = calculate_threshold(VOTERS_NUM, DEFAULT_THRESHOLD_PERCENTAGE);

        let result = ctx.insert_completion_votes(threshold - 1, RANDOM);

        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_insert_failure_vote_success() {
        let mut ctx = TestContext::new()
            .with_voters(VOTERS_NUM)
            .after_proof_deadline()
            .await;

        let result = ctx.insert_failure_votes(VOTERS_NUM);

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_insert_failure_vote_after_vote_deadline() {
        let mut ctx = TestContext::new();
        let peer_id = generate_random_peer_id();

        ctx.process.insert_voter(peer_id).unwrap();
        let mut ctx = ctx.after_vote_deadline().await;

        let result = ctx.process.insert_failure_vote(peer_id);

        assert!(matches!(result, Err(Error::VoteDeadlineReached)));
    }

    #[test]
    fn test_insert_failure_vote_before_proof_deadline() {
        let mut ctx = TestContext::new().with_voters(VOTERS_NUM);
        let peer_id = generate_random_peer_id();

        let result = ctx.process.insert_failure_vote(peer_id);

        assert!(matches!(result, Err(Error::ProofDeadlineNotReached)));
    }

    #[tokio::test]
    async fn test_insert_failure_vote_unknown_peer() {
        let mut ctx = TestContext::new().after_proof_deadline().await;
        let peer_id = generate_random_peer_id();

        let result = ctx.process.insert_failure_vote(peer_id);

        assert!(matches!(result, Err(Error::PeerIdNotFound(_))));
    }

    #[tokio::test]
    async fn test_insert_failure_vote_reach_consensus() {
        let mut ctx = TestContext::new()
            .with_voters(VOTERS_NUM)
            .after_proof_deadline()
            .await;
        let threshold = calculate_threshold(VOTERS_NUM, DEFAULT_THRESHOLD_PERCENTAGE);

        let result = ctx.insert_failure_votes(threshold);

        assert!(result.is_ok());
        assert!(result.unwrap());
        assert_eq!(ctx.process.status, ProcessStatus::Failed);
    }

    #[tokio::test]
    async fn test_insert_failure_vote_not_reach_consensus() {
        let mut ctx = TestContext::new()
            .with_voters(VOTERS_NUM)
            .after_proof_deadline()
            .await;
        let threshold = calculate_threshold(VOTERS_NUM, DEFAULT_THRESHOLD_PERCENTAGE);

        let result = ctx.insert_failure_votes(threshold - 1);

        assert!(result.is_ok());
        assert!(!result.unwrap());
        assert_eq!(ctx.process.status, ProcessStatus::InProgress);
    }

    #[tokio::test]
    async fn test_is_proof_timeout() {
        let ctx = TestContext::new();

        let before_timeout = ctx.process.is_proof_timeout();
        let ctx = ctx.after_proof_deadline().await;
        let after_timeout = ctx.process.is_proof_timeout();

        assert!(!before_timeout);
        assert!(after_timeout);
    }

    #[tokio::test]
    async fn test_is_vote_timeout() {
        let ctx = TestContext::new();

        let before_timeout = ctx.process.is_vote_timeout();
        let ctx = ctx.after_vote_deadline().await;
        let after_timeout = ctx.process.is_vote_timeout();

        assert!(!before_timeout);
        assert!(after_timeout);
    }

    #[test]
    fn test_status() {
        let mut ctx = TestContext::new();
        let initial_status = ctx.process.status;

        ctx.process.status = ProcessStatus::Completed(RANDOM);
        let result = ctx.process.status();

        assert_eq!(initial_status, ProcessStatus::InProgress);
        assert_eq!(result, ProcessStatus::Completed(RANDOM));
    }

    #[tokio::test]
    async fn test_update_status_timeout() {
        let mut ctx = TestContext::new().after_vote_deadline().await;

        let result = ctx.process.update_status();

        assert_eq!(result, ProcessStatus::Failed);
        assert_eq!(ctx.process.status, ProcessStatus::Failed);
    }

    #[tokio::test]
    async fn test_update_status_consensus() {
        let mut ctx = TestContext::new()
            .with_voters(VOTERS_NUM)
            .after_proof_deadline()
            .await;
        let threshold = calculate_threshold(VOTERS_NUM, DEFAULT_THRESHOLD_PERCENTAGE);

        ctx.insert_completion_votes(threshold, RANDOM).unwrap();
        let result = ctx.process.update_status();

        assert!(matches!(result, ProcessStatus::Completed(_)));
    }

    #[test]
    fn test_update_status_no_change() {
        let mut ctx = TestContext::new();

        let result = ctx.process.update_status();

        assert_eq!(result, ProcessStatus::InProgress);
        assert_eq!(ctx.process.status, ProcessStatus::InProgress);
    }

    #[test]
    fn test_proof_deadline() {
        let ctx = TestContext::new();
        let expected = ctx.process.proof_deadline;

        let result = ctx.process.proof_deadline();

        assert_eq!(result, expected);
    }

    #[test]
    fn test_vote_deadline() {
        let ctx = TestContext::new();
        let expected = ctx.process.vote_deadline;

        let result = ctx.process.vote_deadline();

        assert_eq!(result, expected);
    }

    #[test]
    fn test_random_some() {
        let mut ctx = TestContext::new();

        ctx.process.status = ProcessStatus::Completed(RANDOM);
        let result = ctx.process.random();

        assert_eq!(result, Some(RANDOM));
    }

    #[test]
    fn test_random_none() {
        let ctx = TestContext::new();

        let result = ctx.process.random();

        assert_eq!(result, None);
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
        let mut ctx = TestContext::new()
            .with_voters(VOTERS_NUM)
            .after_proof_deadline()
            .await;
        let threshold = calculate_threshold(VOTERS_NUM, DEFAULT_THRESHOLD_PERCENTAGE);

        ctx.insert_completion_votes(threshold, [1u8; 32]).unwrap();
        let elected = ctx.process.elect(ELECTED_NUM).unwrap();

        assert_eq!(elected.len(), ELECTED_NUM);
        for peer_id in elected.iter() {
            assert!(ctx.peer_ids.contains(peer_id));
        }
    }

    #[tokio::test]
    async fn test_elect_insufficient_voters() {
        let ctx = TestContext::new()
            .with_voters(ELECTED_NUM - 1)
            .after_proof_deadline()
            .await;

        let elected = ctx.process.elect(ELECTED_NUM);

        assert!(matches!(elected, Err(Error::InsufficientVoters)));
    }

    #[tokio::test]
    async fn test_elect_before_proof_deadline() {
        let ctx = TestContext::new().with_voters(ELECTED_NUM);

        let elected = ctx.process.elect(ELECTED_NUM);

        assert!(matches!(elected, Err(Error::ProofDeadlineNotReached)));
    }

    #[tokio::test]
    async fn test_elect_after_vote_deadline() {
        let ctx = TestContext::new()
            .with_voters(ELECTED_NUM)
            .after_vote_deadline()
            .await;

        let elected = ctx.process.elect(ELECTED_NUM);

        assert!(matches!(elected, Err(Error::ProofDeadlineReached)));
    }

    #[tokio::test]
    async fn test_elect_process_not_completed() {
        let ctx = TestContext::new()
            .with_voters(VOTERS_NUM)
            .after_proof_deadline()
            .await;

        let elected = ctx.process.elect(ELECTED_NUM);

        assert!(matches!(elected, Err(Error::ProcessNotCompleted)));
    }
}
