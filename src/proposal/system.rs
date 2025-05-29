use std::{sync::Arc, time::SystemTime};

use tokio::{sync::Mutex, time::Duration};

use crate::{
    crypto::keypair::{PublicKey, SecretKey, VrfProof},
    network::transport::{
        self,
        protocols::{gossipsub, kad},
        store::merkle_dag::{self, Node},
    },
    proposal::{
        pool::{self, hash_to_key_array, Pool},
        publisher::{self, generate_candidate_hash, CompleteItem, Publisher},
        vrf_elector::{self, Context as VrfContext, VrfElector},
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

impl<P: Proposal> System<P> {
    pub async fn new(
        transport: Arc<Transport>,
        secret_key: SecretKey,
        total_stake: u32,
        root: Node,
        next_term: SystemTime,
        config: Config,
    ) -> Arc<Self> {
        let pool_config = pool::Config {
            external_topic: POOL_EXTERNAL_TOPIC.to_string(),
        };
        let pool = Pool::new(transport.clone(), pool_config);

        let elector = VrfElector::new(config.expected_num_publishers).with_secret_key(secret_key);
        let publisher = Publisher::new(transport.clone(), elector, secret_key, (&config).into());

        let term_total_duration = config.proposal_collection_duration
            + config.publisher_handle_duration
            + config.network_latency;

        let system = Arc::new(Self {
            transport,
            pool,
            publisher: Mutex::new(publisher),
            elector,
            term_total_duration,
            config,
        });

        tokio::spawn({
            let system = system.clone();
            async move {
                system.run(root, total_stake, next_term).await;
            }
        });

        system
    }

    async fn run(
        self: Arc<Self>,
        mut root: Node,
        mut total_stakes: u32,
        mut next_term: SystemTime,
    ) {
        loop {
            let remaining_time = next_term
                .duration_since(SystemTime::now())
                .expect("Next term time should be in the future");

            tokio::time::sleep(remaining_time).await;

            match self.step(next_term, root.clone(), total_stakes).await {
                Ok((new_root, new_total_stakes)) => {
                    root = new_root;
                    total_stakes = new_total_stakes;
                    log::info!("Step completed");
                }
                Err(e) => {
                    log::error!("Error during step: {e}");
                    continue;
                }
            };

            next_term = next_term
                .checked_add(self.term_total_duration)
                .expect("Next term time overflowed");
        }
    }

    async fn step(&self, start: SystemTime, root: Node, total_stakes: u32) -> Result<(Node, u32)> {
        let root_hash = root.hash().await.expect("Failed to hash root node");
        let vrf_ctx = VrfContext::new(root_hash, total_stakes);

        let calc_result = self.calc_own_times(&root, &vrf_ctx).await?;

        let result = if let Some((proof, times)) = calc_result {
            Some(
                self.handle_elected(root.clone(), proof, times, vrf_ctx)
                    .await?,
            )
        } else {
            self.handle_not_elected(&root, start, &vrf_ctx).await?
        };

        if let Some((item, stakes_impact)) = result {
            let total_stakes = safe_add(total_stakes, stakes_impact);
            Ok((item.final_node, total_stakes))
        } else {
            Ok((root, total_stakes))
        }
    }

    async fn calc_own_times(
        &self,
        root: &Node,
        ctx: &VrfContext,
    ) -> Result<Option<(VrfProof, u32)>> {
        self.get_peer_stakes(&self.transport.self_peer(), root)
            .await?
            .map(|stakes| self.elector.generate(stakes, ctx))
            .transpose()
            .map_err(Error::from)
    }

    async fn get_peer_stakes(&self, peer_id: &libp2p::PeerId, root: &Node) -> Result<Option<u32>> {
        let key = hash_to_key_array(peer_id.to_bytes().try_into().unwrap());

        if let Some(hash) = root.get(key, &self.transport).await? {
            Ok(self.transport.get::<Record>(&hash).await?.map(|r| r.stakes))
        } else {
            Ok(None)
        }
    }

    async fn handle_elected(
        &self,
        root: Node,
        proof: VrfProof,
        times: u32,
        ctx: VrfContext,
    ) -> Result<(CompleteItem, i32)> {
        self.pool.start(root.clone()).await?;

        tokio::time::sleep(self.config.proposal_collection_duration).await;

        let records = self.pool.stop().await?;
        self.publisher
            .lock()
            .await
            .publish(root, records, proof, times, ctx)
            .await
            .map_err(Error::from)
    }

    async fn handle_not_elected(
        &self,
        root: &Node,
        start: SystemTime,
        ctx: &VrfContext,
    ) -> Result<Option<(CompleteItem, i32)>> {
        let mut rx = self
            .transport
            .listen_on_topic(PUBLISHER_EXTERNAL_TOPIC)
            .await?;

        let remaining_time = self.remaining_time(start)?;

        tokio::time::sleep(remaining_time).await;

        tokio::time::timeout(remaining_time, async {
            while let Some(msg) = rx.recv().await {
                if let gossipsub::Payload::ProposalProcessingComplete {
                    final_node,
                    total_stakes_impact,
                    processed,
                    next,
                    proofs,
                } = msg.payload
                {
                    let mut times = self.config.expected_num_publishers;
                    let hash = generate_candidate_hash(&final_node, &processed, &next);

                    for (pk, (proof, sign)) in proofs {
                        if !pk.verify_proof(ctx.input, &proof) {
                            log::warn!("Invalid VRF proof from peer: {}", msg.source);
                            break;
                        }

                        if !pk.verify_signature(hash, &sign) {
                            log::warn!("Invalid signature from peer: {}", msg.source);
                            break;
                        }

                        match self
                            .calc_peer_times(&pk.to_peer_id(), &pk, &proof, root, ctx)
                            .await
                        {
                            Ok(Some(peer_times)) => {
                                if peer_times == 0 {
                                    log::warn!("Peer {} has zero times elected", msg.source);
                                    break;
                                }
                                times = times.saturating_sub(peer_times);
                                if times == 0 {
                                    log::info!("All expected publishers have been processed");

                                    let item = CompleteItem {
                                        final_node: Node::from_slice(&final_node)
                                            .expect("Failed to create node from final_node"),
                                        processed,
                                        next,
                                    };

                                    return Ok(Some((item, total_stakes_impact)));
                                }
                            }
                            Ok(None) => {
                                log::warn!("Failed to calculate peer times for: {}", msg.source);
                                break;
                            }
                            Err(e) => {
                                log::warn!(
                                    "Error calculating peer times for {}: {}",
                                    msg.source,
                                    e
                                );
                                continue;
                            }
                        }
                    }
                }
            }

            Err(Error::ChannelClosed)
        })
        .await
        .unwrap_or_else(|_| {
            log::warn!("Timeout while waiting for proposal processing complete messages");
            Ok(None)
        })
    }

    fn remaining_time(&self, start: SystemTime) -> Result<Duration> {
        let now = SystemTime::now();
        self.term_total_duration
            .checked_sub(now.duration_since(start)?)
            .ok_or(Error::TimeOverflow)
    }

    async fn calc_peer_times(
        &self,
        peer_id: &libp2p::PeerId,
        public_key: &PublicKey,
        proof: &VrfProof,
        root: &Node,
        ctx: &VrfContext,
    ) -> Result<Option<u32>> {
        Ok(self
            .get_peer_stakes(peer_id, root)
            .await?
            .map(|stakes| {
                self.elector
                    .calc_times_with_proof(stakes, public_key, proof, ctx)
            })
            .transpose()?)
    }
}

fn safe_add(a: u32, b: i32) -> u32 {
    if b >= 0 {
        a.saturating_add(b as u32)
    } else {
        a.saturating_sub((-b) as u32)
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
