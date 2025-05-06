use std::{collections::HashSet, sync::Arc, time::SystemTime};

use tokio::sync::mpsc::Receiver as TokioReceiver;

use crate::{
    behaviour::Behaviour,
    committee::{
        self,
        elector::{context::Context, dkg_generator::DkgGenerator},
    },
    crypto::{
        algebra::{Point, Scalar},
        dkg::Dkg,
        keypair::{self, PublicKey, SecretKey, VrfProof},
    },
    network::transport::{
        self,
        protocols::{gossipsub, kad},
    },
    traits::byteable::{self, Byteable},
    utils::{
        consensus_collector::{self, ConsensusCollector},
        IndexedMap,
    },
};

#[cfg(not(test))]
use crate::network::transport::Transport;

#[cfg(test)]
use crate::network::transport::MockTransport as Transport;

pub mod config;

mod context;
mod dkg_generator;

pub use config::Config;

type Result<T> = std::result::Result<T, Error>;

const TRUNCATED_HASH_SIZE: usize = 8;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Transport(#[from] transport::Error),

    #[error("{0}")]
    Keypair(#[from] keypair::Error),

    #[error("{0}")]
    Behaviour(String),

    #[error("{0}")]
    Kad(#[from] kad::Error),

    #[error("{0}")]
    KadPayload(#[from] kad::payload::Error),

    #[error("{0}")]
    ConvertResident(String),

    #[error("Mismatch peer ID: expected {0}, got {1}")]
    MismatchPeerId(libp2p::PeerId, libp2p::PeerId),

    #[error("{0}")]
    Byteable(#[from] byteable::Error),

    #[error("Proof verification failed")]
    ProofVerificationFailed,

    #[error("Proof is outside the valid time range")]
    InvalidTimeRange,

    #[error("{0}")]
    Dkg(String),

    #[error("{0}")]
    DkgGenerator(#[from] dkg_generator::Error),

    #[error("Election failed")]
    ElectionFailed,

    #[error("{0}")]
    Collector(#[from] consensus_collector::Error),
}

pub enum ElectionResult {
    OwnIsMember {
        info: committee::Info,
        invalid_peers: HashSet<libp2p::PeerId>,
        secret: Scalar,
        global_commitments: Vec<Point>,
    },
    OwnIsNotMember {
        info: committee::Info,
    },
}

pub struct Validator {
    pub epoch: u64,
}

pub struct Elector<D: Dkg + 'static> {
    transport: Arc<Transport>,
    generator: DkgGenerator<D>,
    secret_key: SecretKey,
    public_key: PublicKey,
    config: Config,
}

impl<D: Dkg + 'static> Elector<D> {
    pub fn new(
        transport: Arc<Transport>,
        dkg: Arc<D>,
        secret_key: SecretKey,
        config: Config,
    ) -> Self {
        let generator = DkgGenerator::new(transport.clone(), dkg.clone(), (&config).into());
        let public_key = secret_key.to_public_key();

        Self {
            transport,
            generator,
            secret_key,
            public_key,
            config,
        }
    }

    pub async fn start<B: Behaviour>(
        &self,
        base_input: Vec<u8>,
        epoch: u64,
    ) -> Result<ElectionResult> {
        let factor = self.get_selector_factor().await?;
        let mut ctx = Context::new(base_input, epoch, factor);
        let mut rx = self.transport.listen_on_topic(&self.config.topic).await?;

        loop {
            if ctx.times >= self.config.max_attempts {
                break;
            }

            match self.new_round::<B>(&mut ctx, &mut rx).await {
                Ok(Some(result)) => {
                    return Ok(result);
                }
                Ok(None) => {}
                Err(e) => {
                    log::error!("Error during election: {}", e);
                    break;
                }
            }
        }

        Err(Error::ElectionFailed)
    }

    async fn new_round<B: Behaviour>(
        &self,
        ctx: &mut Context,
        rx: &mut TokioReceiver<gossipsub::Message>,
    ) -> Result<Option<ElectionResult>> {
        ctx.increment();
        ctx.clear_candidates();

        let input = ctx.current_input.clone();

        let proof = self.calculate_own_proof::<B>(ctx, &input).await?;
        if let Some((proof, hash)) = proof {
            ctx.add_candidate(
                self.transport.self_peer(),
                proof.output().to_vec()?,
                self.public_key.clone(),
            );
            self.publish_proof(proof.clone(), hash).await?;
        }

        self.collect_proofs::<B>(ctx, rx).await?;

        let candidates = ctx.get_n_candidates(self.config.max_members);

        if candidates.contains_key(&self.transport.self_peer()) {
            self.generate_dkg(ctx, candidates).await
        } else {
            self.collect_dkg_result(ctx, rx, candidates).await
        }
    }

    async fn calculate_own_proof<B: Behaviour>(
        &self,
        ctx: &Context,
        input: &[u8],
    ) -> Result<Option<(VrfProof, [u8; 32])>> {
        let (resident, _, hash) = self.get_resident::<B>(self.transport.self_peer()).await?;

        let weight = B::get_weight(resident).map_err(|e| Error::Behaviour(e.to_string()))?;
        let proof = self.secret_key.prove(input)?;
        let random = self.calculate_random(&proof.output()).await?;

        if (weight as f64) * ctx.selection_factor > random as f64 {
            Ok(Some((proof, hash)))
        } else {
            Ok(None)
        }
    }

    async fn get_resident<B: Behaviour>(
        &self,
        peer_id: libp2p::PeerId,
    ) -> Result<(B::Resident, SystemTime, [u8; 32])> {
        let hash = self
            .transport
            .get_or_error(kad::Key::LatestResident(peer_id))
            .await?
            .extract::<[u8; 32]>(kad::payload::Variant::ResidentKey)?;

        let (resident, timestamp) = self.get_resident_with_hash::<B>(hash, peer_id).await?;

        Ok((resident, timestamp, hash))
    }

    async fn get_resident_with_hash<B: Behaviour>(
        &self,
        hash: [u8; 32],
        expected_peer_id: libp2p::PeerId,
    ) -> Result<(B::Resident, SystemTime)> {
        let (peer_id, bytes, timestamp) = self
            .transport
            .get_or_error(kad::Key::ByHash(hash))
            .await?
            .extract(kad::payload::Variant::Resident)?;

        if expected_peer_id != peer_id {
            return Err(Error::MismatchPeerId(expected_peer_id, peer_id));
        }

        let resident =
            B::Resident::from_slice(&bytes).map_err(|e| Error::ConvertResident(e.to_string()))?;

        Ok((resident, timestamp))
    }

    async fn get_selector_factor(&self) -> Result<f64> {
        let hash = self
            .transport
            .get_or_error(kad::Key::LatestSelectionFactor)
            .await?
            .extract::<[u8; 32]>(kad::payload::Variant::SelectionFactorKey)?;

        self.transport
            .get_or_error(kad::Key::ByHash(hash))
            .await?
            .extract(kad::payload::Variant::SelectionFactor)
            .map_err(Error::from)
    }

    async fn calculate_random(&self, output: &[u8]) -> Result<u64> {
        let hash = blake3::hash(output).as_bytes()[..TRUNCATED_HASH_SIZE]
            .try_into()
            .expect("Hash length is always 8 bytes");

        Ok(u64::from_be_bytes(hash))
    }

    async fn publish_proof(&self, proof: VrfProof, hash: [u8; 32]) -> Result<()> {
        let payload = gossipsub::Payload::ElectionEligibilityProof {
            proof,
            public_key: self.public_key.clone(),
            payload_hash: hash,
        };

        self.transport.publish(&self.config.topic, payload).await?;

        Ok(())
    }

    async fn collect_proofs<B: Behaviour>(
        &self,
        ctx: &mut Context,
        rx: &mut TokioReceiver<gossipsub::Message>,
    ) -> Result<()> {
        let mut interval = tokio::time::interval(self.config.network_latency);

        loop {
            tokio::select! {
                Some(msg) = rx.recv() => {
                    if let gossipsub::Payload::ElectionEligibilityProof { proof, public_key, payload_hash } = msg.payload {
                        if let Err(e) = self.verify_proof::<B>(ctx, msg.source, &proof, &public_key, payload_hash).await {
                            log::error!("Proof verification failed: {}", e);
                        } else {
                            ctx.candidates.insert(msg.source, (proof.output().to_vec()?, public_key));
                        }
                    }
                }
                _ = interval.tick() => {
                    break;
                }
            }
        }

        Ok(())
    }

    async fn verify_proof<B: Behaviour>(
        &self,
        ctx: &Context,
        peer_id: libp2p::PeerId,
        proof: &VrfProof,
        public_key: &PublicKey,
        payload_hash: [u8; 32],
    ) -> Result<()> {
        if public_key.to_peer_id() != peer_id {
            return Err(Error::MismatchPeerId(peer_id, public_key.to_peer_id()));
        }

        let (resident, timestamp) = self
            .get_resident_with_hash::<B>(payload_hash, peer_id)
            .await?;

        if !self.is_lastest_hash(peer_id, payload_hash).await?
            && !self.is_timestamp_valid(ctx, timestamp)
        {
            return Err(Error::InvalidTimeRange);
        }

        let weight = B::get_weight(resident).map_err(|e| Error::Behaviour(e.to_string()))?;
        let random = self.calculate_random(&proof.output()).await?;

        if (weight as f64) * ctx.selection_factor > random as f64 {
            Ok(())
        } else {
            Err(Error::ProofVerificationFailed)
        }
    }

    async fn is_lastest_hash(&self, peer_id: libp2p::PeerId, hash: [u8; 32]) -> Result<bool> {
        let latest_hash = self
            .transport
            .get_or_error(kad::Key::LatestResident(peer_id))
            .await?
            .extract::<[u8; 32]>(kad::payload::Variant::ResidentKey)?;

        Ok(latest_hash == hash)
    }

    fn is_timestamp_valid(&self, ctx: &Context, timestamp: SystemTime) -> bool {
        timestamp >= ctx.start_time
    }

    async fn generate_dkg(
        &self,
        ctx: &mut Context,
        candidates: IndexedMap<libp2p::PeerId, PublicKey>,
    ) -> Result<Option<ElectionResult>> {
        let result = self
            .generator
            .generate(ctx.current_input.clone(), ctx.epoch, candidates)
            .await?;

        match result {
            dkg_generator::GenerateResult::Success {
                info,
                secret,
                global_commitments,
            } => {
                let info = *info;
                let payload = gossipsub::Payload::ElectionSuccess { info: info.clone() };
                self.transport.publish(&self.config.topic, payload).await?;

                let result = ElectionResult::OwnIsMember {
                    info,
                    invalid_peers: std::mem::take(&mut ctx.invalid_peers),
                    secret,
                    global_commitments,
                };

                Ok(Some(result))
            }

            dkg_generator::GenerateResult::Failure(invalid_peers) => {
                ctx.invalid_peers.extend(invalid_peers);
                Ok(None)
            }
        }
    }

    async fn collect_dkg_result(
        &self,
        ctx: &mut Context,
        rx: &mut TokioReceiver<gossipsub::Message>,
        candidates: IndexedMap<libp2p::PeerId, PublicKey>,
    ) -> Result<Option<ElectionResult>> {
        let validator = Validator { epoch: ctx.epoch };
        let collector = ConsensusCollector::new(
            validator,
            self.config.network_latency,
            self.config.threshold_counter,
        );

        let expected_peers = candidates
            .iter()
            .map(|(peer_id, _)| *peer_id)
            .collect::<HashSet<_>>();
        let mut collector = collector.with_expected_peers(expected_peers);
        let result = collector.collect(rx).await?;

        match result {
            Some(info) => {
                let result = ElectionResult::OwnIsNotMember { info };
                Ok(Some(result))
            }
            None => Ok(None),
        }
    }
}

impl consensus_collector::Validator<committee::Info, Error> for Validator {
    async fn validate(&mut self, message: gossipsub::Message) -> Result<Option<committee::Info>> {
        if let gossipsub::Payload::ElectionSuccess { info } = message.payload {
            if self.epoch == info.epoch {
                return Ok(Some(info));
            }
        }

        Ok(None)
    }
}
