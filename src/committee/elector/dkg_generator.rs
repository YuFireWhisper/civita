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

#[derive(Debug)]
pub struct Config {
    pub topic: String,
    pub allowable_time_diff: tokio::time::Duration,
    pub consensus_timeout: tokio::time::Duration,
    pub election_duration: tokio::time::Duration,
    pub threshold_counter: threshold::Counter,
}

pub struct Validator {
    transport: Arc<Transport>,
    proposal_peer: libp2p::PeerId,
    now: SystemTime,
    topic: String,
    election_duration: tokio::time::Duration,
    allowable_time_diff: tokio::time::Duration,
}

pub struct DkgGenerator<D: Dkg> {
    transport: Arc<Transport>,
    dkg: Arc<D>,
    config: Config,
}

impl Validator {
    fn validate_time(&self, end_time: SystemTime) -> bool {
        if let Ok(duration) = end_time.duration_since(self.now) {
            return duration <= self.election_duration + self.allowable_time_diff;
        }
        false
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
            let end_time = now + self.config.election_duration;
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
            election_duration: self.config.election_duration,
            allowable_time_diff: self.config.allowable_time_diff,
        }
    }

    fn create_consensus_collector(
        &self,
        validator: Validator,
        expected_peers: HashSet<libp2p::PeerId>,
    ) -> ConsensusCollector<(SystemTime, bool), Error, Validator> {
        ConsensusCollector::new(
            validator,
            self.config.consensus_timeout,
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
