pub mod process;

use libp2p::PeerId;
use thiserror::Error;
use tokio::time::{Duration, Instant};

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

#[derive(Debug, Clone, PartialEq, Eq, Copy, Hash)]
pub enum ProcessStatus {
    Completed([u8; 32]),
    InProgress,
    Failed,
}

pub trait ConsensusProcess: Send + Sync {
    fn insert_voter(&mut self, peer_id: PeerId) -> Result<(), Error>;
    fn insert_proof(&mut self, proof: Vec<u8>) -> Result<(), Error>;
    fn calculate_consensus(&self) -> Result<[u8; 32], Error>;
    fn insert_completion_vote(
        &mut self,
        peer_id: PeerId,
        random: [u8; 32],
    ) -> Result<Option<[u8; 32]>, Error>;
    fn insert_failure_vote(&mut self, peer_id: PeerId) -> Result<bool, Error>;
    fn is_proof_timeout(&self) -> bool;
    fn is_vote_timeout(&self) -> bool;
    fn status(&mut self) -> ProcessStatus;
    fn update_status(&mut self) -> ProcessStatus;
    fn proof_deadline(&self) -> Instant;
    fn vote_deadline(&self) -> Instant;
    fn random(&self) -> Option<[u8; 32]>;
}

pub trait ConsensusProcessFactory: Send + Sync {
    fn create(
        &self,
        proof_duration: Duration,
        vote_duration: Duration,
    ) -> Box<dyn ConsensusProcess>;
}
