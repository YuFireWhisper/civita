use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use libp2p::PeerId;
use tokio::time::{self, Duration};

use crate::{
    constants::HashArray,
    crypto::keypair::{PublicKey, SecretKey, VrfProof},
    network::transport::{
        self,
        protocols::gossipsub,
        store::merkle_dag::{self, KeyArray, Node},
    },
    proposal::{
        collector::{self, Collector, Context},
        vrf_elector::{self, VrfElector},
        Proposal,
    },
    resident::Record,
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
    VrfElector(#[from] vrf_elector::Error),

    #[error("{0}")]
    Node(#[from] merkle_dag::node::Error),

    #[error("{0}")]
    Collector(#[from] collector::Error),

    #[error("{0}")]
    ProposalToVec(String),

    #[error("{0}")]
    ProposalSerialization(String),

    #[error("Insufficient stake for peer {0}")]
    InsufficientStake(PeerId),

    #[error("Invalid peer or proof for message from {0}")]
    InvalidPeerOrProof(PeerId),
}

pub struct Config {
    pub external_topic: String,
    pub internal_topic: String,
    pub num_members: u32,
    pub network_latency: Duration,
}

#[derive(Clone)]
struct ProposalEntry<P> {
    proposal: P,
    timestamp: u64,
}

#[derive(Clone)]
struct ProposalContext<P> {
    proposals: HashMap<HashArray, ProposalEntry<P>>,
    own_proof: VrfProof,
    own_weight: u32,
    total_stakes: u32,
    input: Vec<u8>,
}

type ProposalKey = (HashArray, u64);

#[derive(Clone)]
struct VoteEntry<P> {
    count: u32,
    proposal: P,
}

struct VoteContext<P> {
    transport: Arc<Transport>,
    votes: HashMap<ProposalKey, VoteEntry<P>>,
    voted_members: HashSet<PeerId>,
    total_times: u32,
    input: Vec<u8>,
    total_stakes: u32,
    elector: Arc<VrfElector>,
    root: Node,
}

pub struct Pool<P: Proposal + Send + Sync + 'static> {
    transport: Arc<Transport>,
    collector: Collector<ProposalContext<P>>,
    public_key: PublicKey,
    elector: Arc<VrfElector>,
    config: Config,
}

impl<P: Proposal + Send + Sync + 'static> ProposalContext<P> {
    pub fn new(input: Vec<u8>, own_proof: VrfProof, own_weight: u32, total_stakes: u32) -> Self {
        Self {
            proposals: HashMap::new(),
            own_proof,
            own_weight,
            total_stakes,
            input,
        }
    }

    fn add_proposal(&mut self, proposal_vec: &[u8]) -> Result<()> {
        let proposal =
            P::from_slice(proposal_vec).map_err(|e| Error::ProposalSerialization(e.to_string()))?;

        let hash = Self::compute_hash(proposal_vec);
        let timestamp = Self::current_timestamp();

        self.proposals.entry(hash).or_insert(ProposalEntry {
            proposal,
            timestamp,
        });

        Ok(())
    }

    fn compute_hash(data: &[u8]) -> HashArray {
        blake3::hash(data).into()
    }

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time should not be before UNIX_EPOCH")
            .as_secs()
            / 60
    }
}

impl<P: Proposal + Send + Sync + 'static> VoteContext<P> {
    fn verify_source(
        &self,
        source: &PeerId,
        public_key: &PublicKey,
        proof: &VrfProof,
    ) -> Result<()> {
        if &public_key.to_peer_id() != source {
            return Err(Error::InvalidPeerOrProof(*source));
        }

        if !public_key.verify_proof(&self.input, proof) {
            return Err(Error::InvalidPeerOrProof(*source));
        }

        if self.voted_members.contains(source) {
            return Err(Error::InvalidPeerOrProof(*source));
        }

        Ok(())
    }

    async fn get_voting_times(&self, peer_id: PeerId, proof: &VrfProof) -> Result<u32> {
        let stakes = self
            .get_peer_stakes(&peer_id)
            .await?
            .ok_or(Error::InsufficientStake(peer_id))?;

        let times = self
            .elector
            .calc_elected_times(stakes, self.total_stakes, &proof.output());

        if times == 0 {
            return Err(Error::InsufficientStake(peer_id));
        }

        Ok(times)
    }

    async fn get_peer_stakes(&self, peer_id: &PeerId) -> Result<Option<u32>> {
        let key = Self::peer_to_key_array(peer_id);
        let hash = self.root.get(key, &self.transport).await?;

        match hash {
            Some(hash) => Ok(self.transport.get::<Record>(&hash).await?.map(|r| r.stakes)),
            None => Ok(None),
        }
    }

    fn peer_to_key_array(peer: &PeerId) -> KeyArray {
        let bytes = peer.to_bytes();
        let mut result = KeyArray::default();

        for (i, chunk) in result.iter_mut().enumerate() {
            let start_idx = i * 2;
            if start_idx + 1 < bytes.len() {
                *chunk = (bytes[start_idx] as u16) << 8 | (bytes[start_idx + 1] as u16);
            }
        }

        result
    }

    fn process_votes(
        &mut self,
        proposals: HashMap<HashArray, (Vec<u8>, u64)>,
        voting_times: u32,
    ) -> Result<()> {
        for (hash, (proposal_vec, timestamp)) in proposals {
            let proposal = P::from_slice(&proposal_vec)
                .map_err(|e| Error::ProposalSerialization(e.to_string()))?;

            let key = (hash, timestamp);
            self.votes
                .entry(key)
                .and_modify(|entry| entry.count += voting_times)
                .or_insert(VoteEntry {
                    count: voting_times,
                    proposal,
                });
        }
        Ok(())
    }
}

impl<P: Proposal + Send + Sync + 'static> Pool<P> {
    pub fn new(transport: Arc<Transport>, secret_key: SecretKey, config: Config) -> Self {
        let public_key = secret_key.to_public_key();
        let elector = VrfElector::new(secret_key.clone(), config.num_members);

        Self {
            transport,
            collector: Collector::new(),
            public_key,
            elector: Arc::new(elector),
            config,
        }
    }

    pub async fn start_proposal_phase(
        &mut self,
        input: Vec<u8>,
        stake: u32,
        total_stakes: u32,
    ) -> Result<()> {
        let (proof, times) = self.elector.generate(&input, stake, total_stakes)?;

        if times == 0 {
            log::info!("No voting rights for this round");
            return Ok(());
        }

        let ctx = ProposalContext::new(input, proof, times, total_stakes);
        let rx = self
            .transport
            .listen_on_topic(&self.config.external_topic)
            .await?;

        self.collector.start(rx, ctx).await;
        Ok(())
    }

    pub async fn start_voting_phase(&mut self, root: Node) -> Result<Vec<P>> {
        let proposal_ctx = self.collector.stop().await?;

        self.publish_own_proposals(&proposal_ctx).await?;

        let vote_ctx = VoteContext {
            transport: self.transport.clone(),
            votes: HashMap::new(),
            voted_members: HashSet::new(),
            total_times: proposal_ctx.own_weight,
            input: proposal_ctx.input,
            total_stakes: proposal_ctx.total_stakes,
            elector: self.elector.clone(),
            root,
        };

        self.collect_votes_and_reach_consensus(vote_ctx).await
    }

    async fn publish_own_proposals(&self, ctx: &ProposalContext<P>) -> Result<()> {
        let proposals = ctx
            .proposals
            .iter()
            .map(|(hash, entry)| {
                let proposal_vec = entry
                    .proposal
                    .to_vec()
                    .map_err(|e| Error::ProposalSerialization(e.to_string()))?;
                Ok((*hash, (proposal_vec, entry.timestamp)))
            })
            .collect::<Result<HashMap<_, _>>>()?;

        if proposals.is_empty() {
            return Ok(());
        }

        let payload = gossipsub::Payload::ConsensusProposal {
            proposals,
            proof: ctx.own_proof.clone(),
            public_key: self.public_key.clone(),
        };

        self.transport
            .publish(&self.config.external_topic, payload)
            .await?;

        log::info!("Published {} proposals", ctx.proposals.len());
        Ok(())
    }

    async fn collect_votes_and_reach_consensus(&self, ctx: VoteContext<P>) -> Result<Vec<P>> {
        let rx = self
            .transport
            .listen_on_topic(&self.config.internal_topic)
            .await?;

        let mut collector = Collector::new();
        collector.start(rx, ctx).await;

        time::sleep(self.config.network_latency).await;

        let vote_ctx = collector.stop().await?;
        self.compute_consensus_result(vote_ctx)
    }

    fn compute_consensus_result(&self, ctx: VoteContext<P>) -> Result<Vec<P>> {
        let threshold = ctx.total_times * 2 / 3;

        let mut accepted_entries: Vec<_> = ctx
            .votes
            .into_iter()
            .filter(|(_, entry)| entry.count >= threshold)
            .collect();

        accepted_entries.sort_by(|((hash_a, ts_a), _), ((hash_b, ts_b), _)| {
            ts_a.cmp(ts_b).then(hash_a.cmp(hash_b))
        });

        let proposals: Vec<_> = accepted_entries
            .into_iter()
            .map(|(_, entry)| entry.proposal)
            .collect();

        Ok(proposals)
    }
}

#[async_trait::async_trait]
impl<P: Proposal + Send + Sync + 'static> Context for ProposalContext<P> {
    async fn handle_message(&mut self, msg: gossipsub::Message) -> bool {
        if let gossipsub::Payload::Proposal(data) = msg.payload {
            if let Err(e) = self.add_proposal(&data) {
                log::warn!("Failed to add proposal: {e}");
            }
        }
        false
    }
}

#[async_trait::async_trait]
impl<P: Proposal + Send + Sync + 'static> Context for VoteContext<P> {
    async fn handle_message(&mut self, msg: gossipsub::Message) -> bool {
        let (proposals, proof, public_key) = match msg.payload {
            gossipsub::Payload::ConsensusProposal {
                proposals,
                proof,
                public_key,
            } => (proposals, proof, public_key),
            _ => return false,
        };

        if let Err(e) = self.verify_source(&msg.source, &public_key, &proof) {
            log::warn!("Invalid message source from {}: {}", msg.source, e);
            return false;
        }

        let voting_times = match self.get_voting_times(msg.source, &proof).await {
            Ok(times) => times,
            Err(e) => {
                log::warn!("Failed to get voting times for {}: {}", msg.source, e);
                return false;
            }
        };

        if let Err(e) = self.process_votes(proposals, voting_times) {
            log::warn!("Failed to process votes from {}: {}", msg.source, e);
            return false;
        }

        self.voted_members.insert(msg.source);
        log::debug!(
            "Processed votes from {} with {} times",
            msg.source,
            voting_times
        );

        false
    }
}

#[cfg(test)]
mod tests {
    use mockall::predicate::*;
    use tokio::sync::mpsc;

    use super::*;
    use crate::{
        crypto::keypair::{self, KeyType},
        network::transport::MockTransport,
        proposal::MockProposal,
    };

    const TEST_EXTERNAL_TOPIC: &str = "test_external";
    const TEST_INTERNAL_TOPIC: &str = "test_internal";
    const TEST_NUM_MEMBERS: u32 = 5;
    const TEST_STAKE: u32 = 100;
    const TEST_TOTAL_STAKES: u32 = 1000;
    const TEST_NETWORK_LATENCY_MS: u64 = 100;
    const TEST_INPUT: &[u8] = b"test_input";

    fn create_test_config() -> Config {
        Config {
            external_topic: TEST_EXTERNAL_TOPIC.to_string(),
            internal_topic: TEST_INTERNAL_TOPIC.to_string(),
            num_members: TEST_NUM_MEMBERS,
            network_latency: Duration::from_millis(TEST_NETWORK_LATENCY_MS),
        }
    }

    fn create_test_input() -> Vec<u8> {
        TEST_INPUT.to_vec()
    }

    fn create_test_node() -> Node {
        let hash = blake3::hash(b"test_data");
        Node::new_with_hash(hash.into())
    }

    fn create_valid_keypair() -> (SecretKey, PublicKey) {
        loop {
            let (secret_key, public_key) = keypair::generate_keypair(KeyType::Secp256k1);
            let elector = VrfElector::new(secret_key.clone(), TEST_NUM_MEMBERS);
            let times = elector
                .generate(TEST_INPUT, TEST_STAKE, TEST_TOTAL_STAKES)
                .unwrap()
                .1;

            if times > 0 {
                break (secret_key, public_key);
            }
        }
    }

    #[tokio::test]
    async fn new_creates_proposal_pool_with_correct_config() {
        let transport = Arc::new(MockTransport::default());
        let (secret_key, _) = keypair::generate_keypair(KeyType::Secp256k1);
        let config = create_test_config();
        let expected_public_key = secret_key.to_public_key();

        let pool = Pool::<MockProposal>::new(transport, secret_key, config);

        assert_eq!(pool.public_key, expected_public_key);
        assert_eq!(pool.config.external_topic, TEST_EXTERNAL_TOPIC);
        assert_eq!(pool.config.internal_topic, TEST_INTERNAL_TOPIC);
        assert_eq!(pool.config.num_members, TEST_NUM_MEMBERS);
    }

    #[tokio::test]
    async fn start_with_zero_times_returns_early() {
        let transport = MockTransport::default();
        let (secret_key, _) = keypair::generate_keypair(KeyType::Secp256k1);
        let config = create_test_config();
        let input = create_test_input();

        // No transport expectations since we should return early
        let mut pool = Pool::<MockProposal>::new(Arc::new(transport), secret_key, config);

        let result = pool.start_proposal_phase(input, 0, TEST_TOTAL_STAKES).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn start_with_positive_times_initializes_context() {
        let mut transport = MockTransport::default();
        transport
            .expect_listen_on_topic()
            .with(eq(TEST_EXTERNAL_TOPIC))
            .times(1)
            .returning(|_| {
                let (_, rx) = mpsc::channel(10);
                Ok(rx)
            });

        let (secret_key, _) = create_valid_keypair();
        let config = create_test_config();
        let input = create_test_input();

        let mut pool = Pool::<MockProposal>::new(Arc::new(transport), secret_key, config);

        let result = pool
            .start_proposal_phase(input.clone(), TEST_STAKE, TEST_TOTAL_STAKES)
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn start_transport_error_propagates() {
        let mut transport = MockTransport::default();
        transport
            .expect_listen_on_topic()
            .with(eq(TEST_EXTERNAL_TOPIC))
            .times(1)
            .returning(|_| Err(transport::Error::MockError));

        let (secret_key, _) = create_valid_keypair();
        let config = create_test_config();

        let mut pool = Pool::<MockProposal>::new(Arc::new(transport), secret_key, config);

        let result = pool
            .start_proposal_phase(TEST_INPUT.to_vec(), TEST_STAKE, TEST_TOTAL_STAKES)
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Transport(_)));
    }

    #[tokio::test]
    async fn stop_without_start_returns_not_started_error() {
        let transport = Arc::new(MockTransport::default());
        let (secret_key, _) = keypair::generate_keypair(KeyType::Secp256k1);
        let config = create_test_config();

        let mut pool = Pool::<MockProposal>::new(transport, secret_key, config);
        let root = create_test_node();

        let result = pool.start_voting_phase(root).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Collector(_)));
    }
}
