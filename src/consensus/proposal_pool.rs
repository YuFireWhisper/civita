use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use libp2p::PeerId;
use tokio::time::Duration;

use crate::{
    consensus::{
        collector::{self, Collector, Context},
        vrf_elector::{self, VrfElector},
    },
    constants::HashArray,
    crypto::keypair::{PublicKey, SecretKey, VrfProof},
    network::transport::{
        self,
        protocols::gossipsub,
        store::merkle_dag::{self, KeyArray, Node},
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
}

pub struct Config {
    pub external_topic: String,
    pub internal_topic: String,
    pub num_members: u32,
    pub network_latency: Duration,
}

#[derive(Clone)]
struct ProposalContext {
    transport: Arc<Transport>,
    proposals: HashSet<HashArray>,
    own_proof: VrfProof,
    own_weight: u32,
    total_stakes: u32,
    input: Vec<u8>,
}

struct VoteContext {
    transport: Arc<Transport>,
    votes: HashMap<HashArray, u32>,
    voted_members: HashSet<PeerId>,
    total_times: u32,
    input: Vec<u8>,
    total_stakes: u32,
    elector: Arc<VrfElector>,
    root: Node,
}

pub struct ProposalPool {
    transport: Arc<Transport>,
    collector: Collector<ProposalContext>,
    public_key: PublicKey,
    elector: Arc<VrfElector>,
    config: Config,
}

impl VoteContext {
    async fn get_stakes(&self, peer_id: PeerId) -> Result<Option<u32>> {
        let key = Self::peer_to_key_array(&peer_id);
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
            if i * 2 + 1 < bytes.len() {
                let high = bytes[i * 2] as u16;
                let low = bytes[i * 2 + 1] as u16;
                *chunk = (high << 8) | low;
            }
        }

        result
    }
}

impl ProposalPool {
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

    pub async fn start(&mut self, input: Vec<u8>, stake: u32, total_stakes: u32) -> Result<()> {
        let (proof, times) = self.elector.generate(&input, stake, total_stakes)?;

        if times == 0 {
            return Ok(());
        }

        let ctx = ProposalContext {
            transport: self.transport.clone(),
            proposals: HashSet::new(),
            own_proof: proof.clone(),
            own_weight: times,
            total_stakes,
            input: input.clone(),
        };

        let rx = self
            .transport
            .listen_on_topic(&self.config.external_topic)
            .await?;

        self.collector.start(rx, ctx).await;

        Ok(())
    }

    pub async fn stop(&mut self, root: Node) -> Result<HashSet<HashArray>> {
        let ctx = self.collector.stop().await?;

        let own_proposals = ctx.proposals.clone();

        self.publish_proposals(own_proposals, ctx.own_proof.clone())
            .await?;

        let vote_ctx = VoteContext {
            transport: self.transport.clone(),
            votes: HashMap::new(),
            voted_members: HashSet::new(),
            total_times: ctx.own_weight,
            input: ctx.input,
            total_stakes: ctx.total_stakes,
            elector: self.elector.clone(),
            root,
        };

        self.collect_and_vote(vote_ctx).await
    }

    async fn publish_proposals(
        &self,
        proposals: HashSet<HashArray>,
        proof: VrfProof,
    ) -> Result<()> {
        let payload = gossipsub::Payload::ConsensusProposal {
            proposals,
            proof,
            public_key: self.public_key.clone(),
        };

        self.transport
            .publish(&self.config.external_topic, payload)
            .await?;

        Ok(())
    }

    async fn collect_and_vote(&self, ctx: VoteContext) -> Result<HashSet<HashArray>> {
        let rx = self
            .transport
            .listen_on_topic(&self.config.internal_topic)
            .await?;

        let mut collector = Collector::new();
        collector.start(rx, ctx).await;

        tokio::time::sleep(self.config.network_latency).await;

        let ctx = collector.stop().await?;
        let threshold = ctx.total_times * 2 / 3;

        Ok(ctx
            .votes
            .into_iter()
            .filter(|(_, count)| count >= &threshold)
            .map(|(hash, _)| hash)
            .collect())
    }
}

#[async_trait::async_trait]
impl collector::Context for ProposalContext {
    async fn handle_message(&mut self, msg: gossipsub::Message) -> bool {
        if let gossipsub::Payload::Proposal(hash) = msg.payload {
            if self.transport.get_or_error::<Node>(&hash).await.is_ok() {
                self.proposals.insert(hash);
            }
        }

        false
    }
}

#[async_trait::async_trait]
impl Context for VoteContext {
    async fn handle_message(&mut self, msg: gossipsub::Message) -> bool {
        let (proposals, proof, public_key) = match msg.payload {
            gossipsub::Payload::ConsensusProposal {
                proposals,
                proof,
                public_key,
            } => (proposals, proof, public_key),
            _ => return false,
        };

        if !public_key.verify_proof(&self.input, &proof) {
            return false;
        }

        if self.voted_members.contains(&msg.source) {
            return false;
        }

        let stakes = match self.get_stakes(msg.source).await {
            Ok(Some(stakes)) => stakes,
            Ok(None) => return false,
            Err(_) => return false,
        };

        let times = self
            .elector
            .calc_elected_times(stakes, self.total_stakes, &proof.output());

        if times == 0 {
            return false;
        }

        proposals.iter().for_each(|proposal| {
            self.votes
                .entry(*proposal)
                .and_modify(|e| *e += times)
                .or_insert(times);
        });

        self.voted_members.insert(msg.source);

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

        let pool = ProposalPool::new(transport, secret_key, config);

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
        let mut pool = ProposalPool::new(Arc::new(transport), secret_key, config);

        let result = pool.start(input, 0, TEST_TOTAL_STAKES).await;

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

        let mut pool = ProposalPool::new(Arc::new(transport), secret_key, config);

        let result = pool
            .start(input.clone(), TEST_STAKE, TEST_TOTAL_STAKES)
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

        let mut pool = ProposalPool::new(Arc::new(transport), secret_key, config);

        let result = pool
            .start(TEST_INPUT.to_vec(), TEST_STAKE, TEST_TOTAL_STAKES)
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Transport(_)));
    }

    #[tokio::test]
    async fn stop_without_start_returns_not_started_error() {
        let transport = Arc::new(MockTransport::default());
        let (secret_key, _) = keypair::generate_keypair(KeyType::Secp256k1);
        let config = create_test_config();

        let mut pool = ProposalPool::new(transport, secret_key, config);
        let root = create_test_node();

        let result = pool.stop(root).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Collector(_)));
    }
}
