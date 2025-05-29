use std::{sync::Arc, time::SystemTime};

use tokio::{sync::Mutex, time::Duration};

use crate::{
    constants::HashArray,
    crypto::keypair::{PublicKey, ResidentSignature, SecretKey, VrfProof},
    network::transport::{
        self,
        protocols::{gossipsub, kad},
        store::merkle_dag::{self, Node},
    },
    proposal::{
        pool::{self, hash_to_key_array, CollectedRecords, Pool},
        publisher::{self, generate_candidate_hash, CompleteItem, Publisher},
        vrf_elector::{self, Context as VrfContext, ElectionResult, VrfElector},
        Proposal,
    },
    resident::Record,
};

#[cfg(not(test))]
use crate::network::transport::Transport;

#[cfg(test)]
use crate::network::transport::MockTransport as Transport;

type Result<T> = std::result::Result<T, Error>;

const POOL_EXTERNAL_TOPIC: &str = "proposal_pool";
const PUBLISHER_EXTERNAL_TOPIC: &str = "proposal_publisher";
const PUBLISHER_INTERNAL_TOPIC: &str = "proposal_publisher_internal";

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Transport(#[from] transport::Error),

    #[error("{0}")]
    VrfElector(#[from] vrf_elector::Error),

    #[error("{0}")]
    Node(#[from] merkle_dag::node::Error),

    #[error("{0}")]
    Kad(#[from] kad::Error),

    #[error("Start time is in the past")]
    PastStartTime(#[from] std::time::SystemTimeError),

    #[error("Time calculation is overflowed")]
    TimeOverflow,

    #[error("Channel closed")]
    ChannelClosed,

    #[error("{0}")]
    Pool(#[from] pool::Error),

    #[error("{0}")]
    Publisher(#[from] publisher::Error),
}

#[derive(Clone)]
pub struct Config {
    pub proposal_collection_duration: Duration,
    pub publisher_handle_duration: Duration,
    pub network_latency: Duration,
    pub batch_size: usize,
    pub max_records_per_term: usize,
    pub expected_num_publishers: u32,
}

pub struct System<P: Proposal> {
    transport: Arc<Transport>,
    pool: Pool<P>,
    publisher: Mutex<Publisher>,
    elector: VrfElector,
    term_total_duration: Duration,
    config: Config,
}

struct ProcessingResult {
    final_node: Node,
    stakes_impact: i32,
}

#[derive(Clone)]
struct TermState {
    root: Node,
    total_stakes: u32,
    start: SystemTime,
}

impl<P: Proposal> System<P> {
    pub async fn new(
        transport: Arc<Transport>,
        secret_key: SecretKey,
        config: Config,
    ) -> Arc<Self> {
        Arc::new(Self {
            transport: transport.clone(),
            pool: Self::create_pool(transport.clone()),
            publisher: Mutex::new(Self::create_publisher(transport, secret_key, &config)),
            elector: VrfElector::new(config.expected_num_publishers).with_secret_key(secret_key),
            term_total_duration: Self::calculate_term_duration(&config),
            config,
        })
    }

    fn create_pool(transport: Arc<Transport>) -> Pool<P> {
        let pool_config = pool::Config {
            external_topic: POOL_EXTERNAL_TOPIC.to_string(),
        };
        Pool::new(transport, pool_config)
    }

    fn create_publisher(
        transport: Arc<Transport>,
        secret_key: SecretKey,
        config: &Config,
    ) -> Publisher {
        Publisher::new(
            transport,
            VrfElector::new(config.expected_num_publishers),
            secret_key,
            config.into(),
        )
    }

    fn calculate_term_duration(config: &Config) -> Duration {
        config.proposal_collection_duration
            + config.publisher_handle_duration
            + config.network_latency
    }

    pub async fn start(self: Arc<Self>, root: Node, total_stakes: u32, start_time: SystemTime) {
        tokio::spawn(async move {
            let mut state = TermState {
                root,
                total_stakes,
                start: start_time,
            };

            loop {
                match self.execute_term_cycle(&mut state).await {
                    Ok(_) => {
                        log::info!("Term cycle completed successfully");
                    }
                    Err(e) => {
                        log::error!("Error during term cycle: {e}");
                    }
                }
            }
        });
    }

    async fn execute_term_cycle(&self, state: &mut TermState) -> Result<()> {
        Self::wait_for_term_start(state.start).await?;

        let vrf_ctx = Self::create_vrf_context(state).await?;
        let election_result = self.check_election_status(&state.root, &vrf_ctx).await?;

        let processing_result = match election_result {
            Some(election) => {
                self.handle_publisher_role(state.root.clone(), election, vrf_ctx)
                    .await?
            }
            None => {
                self.handle_observer_role(&state.root, state.start, &vrf_ctx)
                    .await?
            }
        };

        self.update_state(state, processing_result);

        Ok(())
    }

    async fn wait_for_term_start(start: SystemTime) -> Result<()> {
        let remaining_time = start.duration_since(SystemTime::now())?;
        tokio::time::sleep(remaining_time).await;
        Ok(())
    }

    async fn create_vrf_context(state: &TermState) -> Result<VrfContext> {
        let root_hash = state.root.hash().await.expect("Failed to hash root node");
        Ok(VrfContext::new(root_hash, state.total_stakes))
    }

    async fn check_election_status(
        &self,
        root: &Node,
        vrf_ctx: &VrfContext,
    ) -> Result<Option<ElectionResult>> {
        Ok(self
            .get_peer_stakes(&self.transport.self_peer(), root)
            .await?
            .map(|stakes| self.elector.generate(stakes, vrf_ctx))
            .transpose()?)
    }

    async fn get_peer_stakes(&self, peer_id: &libp2p::PeerId, root: &Node) -> Result<Option<u32>> {
        let key = hash_to_key_array(peer_id.to_bytes().try_into().unwrap());

        match root.get(key, &self.transport).await? {
            Some(hash) => {
                let record = self.transport.get::<Record>(&hash).await?;
                Ok(record.map(|r| r.stakes))
            }
            None => Ok(None),
        }
    }

    async fn handle_publisher_role(
        &self,
        root: Node,
        election: ElectionResult,
        ctx: VrfContext,
    ) -> Result<Option<ProcessingResult>> {
        let records = self.collect_proposals(root.clone()).await?;
        let complete_item = self.publish_proposals(root, records, election, ctx).await?;

        Ok(Some(ProcessingResult {
            final_node: complete_item.0.final_node,
            stakes_impact: complete_item.1,
        }))
    }

    async fn collect_proposals(&self, root: Node) -> Result<CollectedRecords> {
        self.pool.start(root).await?;
        tokio::time::sleep(self.config.proposal_collection_duration).await;
        self.pool.stop().await.map_err(Error::from)
    }

    async fn publish_proposals(
        &self,
        root: Node,
        records: CollectedRecords,
        election: ElectionResult,
        ctx: VrfContext,
    ) -> Result<(CompleteItem, i32)> {
        self.publisher
            .lock()
            .await
            .publish(root, records, election, ctx)
            .await
            .map_err(Error::from)
    }

    async fn handle_observer_role(
        &self,
        root: &Node,
        start_time: SystemTime,
        ctx: &VrfContext,
    ) -> Result<Option<ProcessingResult>> {
        let mut receiver = self
            .transport
            .listen_on_topic(PUBLISHER_EXTERNAL_TOPIC)
            .await?;
        let timeout_duration = self.calculate_remaining_time(start_time)?;

        tokio::time::timeout(timeout_duration, async {
            self.process_external_messages(&mut receiver, root, ctx)
                .await
        })
        .await
        .unwrap_or_else(|_| {
            log::warn!("Timeout while waiting for external messages");
            Ok(None)
        })
    }

    fn calculate_remaining_time(&self, start: SystemTime) -> Result<Duration> {
        let elapsed = SystemTime::now().duration_since(start)?;
        self.term_total_duration
            .checked_sub(elapsed)
            .ok_or(Error::TimeOverflow)
    }

    async fn process_external_messages(
        &self,
        receiver: &mut tokio::sync::mpsc::Receiver<gossipsub::Message>,
        root: &Node,
        ctx: &VrfContext,
    ) -> Result<Option<ProcessingResult>> {
        let mut remaining_publishers = self.config.expected_num_publishers;

        while let Some(msg) = receiver.recv().await {
            match self
                .process_single_message(msg, root, ctx, &mut remaining_publishers)
                .await?
            {
                Some(result) => return Ok(Some(result)),
                None => continue,
            }
        }

        Err(Error::ChannelClosed)
    }

    async fn process_single_message(
        &self,
        msg: gossipsub::Message,
        root: &Node,
        ctx: &VrfContext,
        remaining_publishers: &mut u32,
    ) -> Result<Option<ProcessingResult>> {
        let gossipsub::Payload::ProposalProcessingComplete {
            final_node,
            total_stakes_impact,
            processed,
            next,
            proofs,
        } = msg.payload
        else {
            return Ok(None);
        };

        let candidate_hash = generate_candidate_hash(&final_node, &processed, &next);

        for (public_key, (proof, signature)) in proofs {
            if !self.validate_proof_and_signature(
                &public_key,
                &proof,
                &signature,
                ctx,
                &candidate_hash,
            ) {
                log::warn!("Invalid proof or signature from peer: {}", msg.source);
                break;
            }

            let times = match self
                .get_peer_times(&public_key.to_peer_id(), &proof, root, ctx)
                .await?
            {
                Some(times) => times,
                None => {
                    log::warn!("Failed to get peer times for: {}", msg.source);
                    break;
                }
            };

            if times == 0 {
                log::warn!("Peer {} has zero election times", msg.source);
                break;
            }

            *remaining_publishers = remaining_publishers.saturating_sub(times);

            if *remaining_publishers == 0 {
                log::info!("All expected publishers processed");
                return Ok(Some(ProcessingResult {
                    final_node: Node::from_slice(&final_node)
                        .expect("Failed to create node from final_node"),
                    stakes_impact: total_stakes_impact,
                }));
            }
        }

        Ok(None)
    }

    fn validate_proof_and_signature(
        &self,
        public_key: &PublicKey,
        proof: &VrfProof,
        signature: &ResidentSignature,
        ctx: &VrfContext,
        candidate_hash: &HashArray,
    ) -> bool {
        public_key.verify_proof(ctx.input, proof)
            && public_key.verify_signature(candidate_hash, signature)
    }

    async fn get_peer_times(
        &self,
        peer_id: &libp2p::PeerId,
        proof: &VrfProof,
        root: &Node,
        ctx: &VrfContext,
    ) -> Result<Option<u32>> {
        Ok(self
            .get_peer_stakes(peer_id, root)
            .await?
            .map(|stakes| self.elector.calc_times_with_proof(stakes, proof, ctx))
            .transpose()?)
    }

    fn update_state(&self, state: &mut TermState, result: Option<ProcessingResult>) {
        if let Some(result) = result {
            state.root = result.final_node;
            state.total_stakes = safe_add(state.total_stakes, result.stakes_impact);
        }

        state.start = state
            .start
            .checked_add(self.term_total_duration)
            .expect("Next term time overflowed");
    }
}

#[inline]
fn safe_add(a: u32, b: i32) -> u32 {
    match b.cmp(&0) {
        std::cmp::Ordering::Greater => a.saturating_add(b as u32),
        std::cmp::Ordering::Less => a.saturating_sub((-b) as u32),
        std::cmp::Ordering::Equal => a,
    }
}

impl From<&Config> for publisher::Config {
    fn from(config: &Config) -> Self {
        publisher::Config {
            batch_size: config.batch_size,
            max_records_per_term: config.max_records_per_term,
            network_latency: config.network_latency,
            external_topic: PUBLISHER_EXTERNAL_TOPIC.to_string(),
            internal_topic: PUBLISHER_INTERNAL_TOPIC.to_string(),
        }
    }
}
