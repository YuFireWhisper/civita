use std::sync::Arc;

use dashmap::DashMap;
use libp2p::{gossipsub::MessageId, PeerId};
use thiserror::Error;
use tokio::time::{Duration, Instant};

use super::process::{self, ConsensusProcess, ConsensusProcessFactory, ProcessStatus};

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Process(#[from] process::Error),
    #[error("Process not found")]
    ProcessNotFound,
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

    pub fn insert_completion_vote(
        &self,
        message_id: &MessageId,
        peer_id: PeerId,
        random: [u8; 32],
    ) -> Result<Option<[u8; 32]>> {
        self.processes
            .get_mut(message_id)
            .ok_or(Error::ProcessNotFound)?
            .insert_completion_vote(peer_id, random)
            .map_err(Error::from)
    }

    pub fn insert_failure_vote(&self, message_id: &MessageId, peer_id: PeerId) -> Result<bool> {
        self.processes
            .get_mut(message_id)
            .ok_or(Error::ProcessNotFound)?
            .insert_failure_vote(peer_id)
            .map_err(Error::from)
    }

    pub fn status(&self, message_id: &MessageId) -> Result<ProcessStatus> {
        self.processes
            .get_mut(message_id)
            .ok_or(Error::ProcessNotFound)
            .map(|mut process| process.status())
    }

    pub fn proof_deadline(&self, message_id: &MessageId) -> Result<Instant> {
        self.processes
            .get(message_id)
            .ok_or(Error::ProcessNotFound)
            .map(|process| *process.proof_deadline())
    }

    pub fn random(&self, message_id: &MessageId) -> Result<Option<[u8; 32]>> {
        self.processes
            .get_mut(message_id)
            .ok_or(Error::ProcessNotFound)
            .map(|process| process.random().cloned())
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
