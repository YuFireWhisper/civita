use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use libp2p::PeerId;
use tokio::time::Duration;

use crate::{
    consensus::{
        proposal_pool::{
            member_manager::MemberManager, proposal_collector::ProposalCollector,
            signature_collector::SignatureCollector, vote_manager::VoteManager,
        },
        signed_result::SignedResult,
        vrf_elector::{self, VrfElector},
    },
    constants::HashArray,
    crypto::keypair::{self, PublicKey, ResidentSignature, SecretKey, VrfProof},
    network::transport::{
        self,
        protocols::gossipsub,
        store::merkle_dag::{self, Node},
    },
};

#[cfg(not(test))]
use crate::network::transport::Transport;

#[cfg(test)]
use crate::network::transport::MockTransport as Transport;

mod member_manager;
mod proposal_collector;
mod signature_collector;
mod vote_manager;

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
    Keypair(#[from] keypair::Error),

    #[error("{0}")]
    Collector(#[from] proposal_collector::Error),

    #[error("Proposal pool not started")]
    NotStarted,

    #[error("{0}")]
    MemberManager(#[from] member_manager::Error),
}

pub struct Config {
    pub external_topic: String,
    pub internal_topic: String,
    pub num_members: u32,
    pub network_latency: Duration,
}

struct Context {
    proposal_collector: ProposalCollector,
    own_proof: VrfProof,
    own_weight: u32,
    own_proposals: Option<HashSet<HashArray>>,
    root: Option<Node>,
    total_stakes: u32,
    input: Vec<u8>,
}

pub struct ProposalPool {
    transport: Arc<Transport>,
    secret_key: SecretKey,
    public_key: PublicKey,
    elector: Arc<VrfElector>,
    ctx: Option<Context>,
    config: Config,
}

impl Context {
    pub fn own_proposals_or_unwrap(&self) -> HashSet<HashArray> {
        self.own_proposals
            .as_ref()
            .expect("Proposals should be present")
            .clone()
    }

    pub fn root_or_unwrap(&self) -> Node {
        self.root.clone().expect("Root should be present")
    }
}

impl ProposalPool {
    pub fn new(transport: Arc<Transport>, secret_key: SecretKey, config: Config) -> Self {
        let public_key = secret_key.to_public_key();
        let elector = VrfElector::new(secret_key.clone(), config.num_members);

        Self {
            transport,
            secret_key,
            public_key,
            elector: Arc::new(elector),
            ctx: None,
            config,
        }
    }

    pub async fn start(&mut self, input: Vec<u8>, stake: u32, total_stakes: u32) -> Result<()> {
        let (proof, times) = self.elector.generate(&input, stake, total_stakes)?;

        if times == 0 {
            return Ok(());
        }

        let mut collector = ProposalCollector::new(self.transport.clone());
        collector.start(&self.config.external_topic).await?;

        let ctx = Context {
            proposal_collector: collector,
            own_proof: proof,
            own_weight: times,
            own_proposals: None,
            root: None,
            total_stakes,
            input,
        };

        self.ctx = Some(ctx);

        Ok(())
    }

    pub async fn settle(&mut self, root: Node) -> Result<SignedResult<HashSet<HashArray>>> {
        let mut ctx = self.ctx.take().ok_or(Error::NotStarted)?;

        ctx.own_proposals = Some(ctx.proposal_collector.settle().await?);
        ctx.root = Some(root);
        self.publish_proposals(&ctx).await?;
        let (final_proposals, members) = self.collect_and_vote(&ctx).await?;

        self.consensus_result(final_proposals, members).await
    }

    async fn publish_proposals(&self, ctx: &Context) -> Result<()> {
        let payload = gossipsub::Payload::ConsensusProposal {
            proposal_set: ctx.own_proposals_or_unwrap(),
            proof: ctx.own_proof.clone(),
            public_key: self.public_key.clone(),
        };

        self.transport
            .publish(&self.config.external_topic, payload)
            .await?;

        Ok(())
    }

    async fn collect_and_vote(
        &self,
        ctx: &Context,
    ) -> Result<(HashSet<HashArray>, HashMap<PeerId, (PublicKey, VrfProof)>)> {
        let mut rx = self
            .transport
            .listen_on_topic(&self.config.internal_topic)
            .await?;

        let mut member_manager = MemberManager::new(
            self.transport.clone(),
            self.elector.clone(),
            ctx.input.clone(),
            ctx.total_stakes,
            ctx.root_or_unwrap(),
        );
        member_manager
            .add_member(
                self.transport.self_peer(),
                self.public_key.clone(),
                ctx.own_proof.clone(),
            )
            .await?;

        let mut vote_manager = VoteManager::new();
        vote_manager.add_votes(ctx.own_proposals_or_unwrap().iter(), ctx.own_weight);
        vote_manager.add_total_votes(ctx.own_weight);

        while let Some(msg) = rx.recv().await {
            if let gossipsub::Payload::ConsensusProposal {
                proposal_set,
                proof,
                public_key,
            } = msg.payload
            {
                if let Ok(Some(times)) = member_manager
                    .add_member(msg.source, public_key, proof)
                    .await
                {
                    vote_manager.add_votes(proposal_set.iter(), times);
                    vote_manager.add_total_votes(times);
                }
            }
        }

        Ok((
            vote_manager.get_winners(),
            member_manager.get_member_proofs(),
        ))
    }

    pub async fn consensus_result(
        &self,
        final_proposals: HashSet<HashArray>,
        members: HashMap<PeerId, (PublicKey, VrfProof)>,
    ) -> Result<SignedResult<HashSet<HashArray>>> {
        let final_hash = self.calc_final_hash(&final_proposals);

        let signature = self.secret_key.sign(final_hash)?;

        self.publish_signature(signature).await?;

        let signatures = self.collect_signatures(final_hash, members).await?;

        Ok(SignedResult {
            result: final_proposals,
            members: signatures,
        })
    }

    fn calc_final_hash(&self, final_proposals: &HashSet<HashArray>) -> HashArray {
        let mut hasher = blake3::Hasher::new();
        let mut sorted_proposals: Vec<_> = final_proposals.iter().collect();
        sorted_proposals.sort();

        for proposal in sorted_proposals {
            hasher.update(proposal);
        }

        hasher.finalize().into()
    }

    async fn publish_signature(&self, signature: ResidentSignature) -> Result<()> {
        let payload = gossipsub::Payload::ConsensusProposalResult { signature };

        self.transport
            .publish(&self.config.internal_topic, payload)
            .await?;

        Ok(())
    }

    async fn collect_signatures(
        &self,
        final_hash: HashArray,
        mut members: HashMap<PeerId, (PublicKey, VrfProof)>,
    ) -> Result<HashMap<PublicKey, (VrfProof, ResidentSignature)>> {
        let mut rx = self
            .transport
            .listen_on_topic(&self.config.internal_topic)
            .await?;

        let mut collector = SignatureCollector::new(final_hash);

        while let Some(msg) = rx.recv().await {
            let (public_key, proof) = match members.remove(&msg.source) {
                Some((public_key, proof)) => (public_key, proof),
                None => continue,
            };

            if let gossipsub::Payload::ConsensusProposalResult { signature } = msg.payload {
                collector.add_signature(public_key, proof, signature);
            }
        }

        Ok(collector.get_signatures())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::keypair::{self, KeyType},
        network::transport::{
            protocols::gossipsub::{Message, Payload},
            MockTransport,
        },
    };
    use libp2p::{gossipsub::MessageId, PeerId};
    use mockall::predicate::*;
    use std::collections::{HashMap, HashSet};
    use tokio::sync::mpsc;

    // Test constants
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

    fn create_test_hash_set() -> HashSet<HashArray> {
        let mut set = HashSet::new();
        set.insert([1u8; 32]);
        set.insert([2u8; 32]);
        set
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
        assert!(pool.ctx.is_none());
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
        assert!(pool.ctx.is_none());
    }

    #[tokio::test]
    async fn start_with_positive_times_initializes_context() {
        let mut transport = MockTransport::default();
        transport
            .expect_listen_on_topic()
            .with(eq(TEST_EXTERNAL_TOPIC))
            .times(1)
            .returning(|_| {
                let (tx, rx) = mpsc::channel(10);
                drop(tx); // Close channel immediately
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
        assert!(pool.ctx.is_some());

        let ctx = pool.ctx.as_ref().unwrap();
        assert_eq!(ctx.input, input);
        assert_eq!(ctx.total_stakes, TEST_TOTAL_STAKES);
        assert!(ctx.own_proposals.is_none());
        assert!(ctx.root.is_none());
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
        assert!(matches!(result.unwrap_err(), Error::Collector(_)));
    }

    #[tokio::test]
    async fn settle_without_start_returns_not_started_error() {
        let transport = Arc::new(MockTransport::default());
        let (secret_key, _) = keypair::generate_keypair(KeyType::Secp256k1);
        let config = create_test_config();

        let mut pool = ProposalPool::new(transport, secret_key, config);
        let root = create_test_node();

        let result = pool.settle(root).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::NotStarted));
    }

    #[tokio::test]
    async fn calc_final_hash_produces_consistent_results() {
        let transport = Arc::new(MockTransport::default());
        let (secret_key, _) = keypair::generate_keypair(KeyType::Secp256k1);
        let config = create_test_config();

        let pool = ProposalPool::new(transport, secret_key, config);
        let proposals = create_test_hash_set();

        let hash1 = pool.calc_final_hash(&proposals);
        let hash2 = pool.calc_final_hash(&proposals);

        assert_eq!(hash1, hash2);
    }

    #[tokio::test]
    async fn calc_final_hash_different_for_different_proposals() {
        let transport = Arc::new(MockTransport::default());
        let (secret_key, _) = keypair::generate_keypair(KeyType::Secp256k1);
        let config = create_test_config();

        let pool = ProposalPool::new(transport, secret_key, config);

        let mut proposals1 = HashSet::new();
        proposals1.insert([1u8; 32]);

        let mut proposals2 = HashSet::new();
        proposals2.insert([2u8; 32]);

        let hash1 = pool.calc_final_hash(&proposals1);
        let hash2 = pool.calc_final_hash(&proposals2);

        assert_ne!(hash1, hash2);
    }

    #[tokio::test]
    async fn publish_signature_calls_transport_publish() {
        let mut transport = MockTransport::default();
        let (secret_key, _) = keypair::generate_keypair(KeyType::Secp256k1);
        let signature = secret_key.sign(b"test").unwrap();

        transport
            .expect_publish()
            .with(
                eq(TEST_INTERNAL_TOPIC),
                eq(Payload::ConsensusProposalResult {
                    signature: signature.clone(),
                }),
            )
            .times(1)
            .returning(|_, _| Ok(MessageId::new(b"test_id")));

        let config = create_test_config();
        let pool = ProposalPool::new(Arc::new(transport), secret_key, config);

        let result = pool.publish_signature(signature).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn publish_signature_transport_error_propagates() {
        let mut transport = MockTransport::default();
        let (secret_key, _) = keypair::generate_keypair(KeyType::Secp256k1);
        let signature = secret_key.sign(b"test").unwrap();

        transport
            .expect_publish()
            .times(1)
            .returning(|_, _| Err(transport::Error::MockError));

        let config = create_test_config();
        let pool = ProposalPool::new(Arc::new(transport), secret_key, config);

        let result = pool.publish_signature(signature).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Transport(_)));
    }

    #[tokio::test]
    async fn collect_signatures_handles_empty_members() {
        let mut transport = MockTransport::default();
        let (tx, rx) = mpsc::channel(10);

        transport
            .expect_listen_on_topic()
            .with(eq(TEST_INTERNAL_TOPIC))
            .times(1)
            .return_once(move |_| Ok(rx));

        drop(tx);

        let (secret_key, _) = keypair::generate_keypair(KeyType::Secp256k1);
        let config = create_test_config();
        let pool = ProposalPool::new(Arc::new(transport), secret_key, config);

        let final_hash = [0u8; 32];
        let members = HashMap::new();

        let result = pool.collect_signatures(final_hash, members).await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn collect_signatures_filters_unknown_peers() {
        let mut transport = MockTransport::default();
        let (tx, rx) = mpsc::channel(10);

        transport
            .expect_listen_on_topic()
            .with(eq(TEST_INTERNAL_TOPIC))
            .times(1)
            .return_once(move |_| Ok(rx));

        let (secret_key, _) = keypair::generate_keypair(KeyType::Secp256k1);
        let signature = secret_key.sign(b"test").unwrap();

        // Send message from unknown peer
        let unknown_peer = PeerId::random();
        let message = Message {
            message_id: MessageId::new(b"test"),
            source: unknown_peer,
            topic: TEST_INTERNAL_TOPIC.to_string(),
            payload: Payload::ConsensusProposalResult { signature },
            committee_signature: None,
        };

        tokio::spawn(async move {
            tx.send(message).await.unwrap();
        });

        let config = create_test_config();
        let pool = ProposalPool::new(Arc::new(transport), secret_key, config);

        let final_hash = [0u8; 32];
        let members = HashMap::new(); // No known members

        let result = pool.collect_signatures(final_hash, members).await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn collect_signatures_processes_valid_signatures() {
        let mut transport = MockTransport::default();
        let (tx, rx) = mpsc::channel(10);

        transport
            .expect_listen_on_topic()
            .with(eq(TEST_INTERNAL_TOPIC))
            .times(1)
            .return_once(move |_| Ok(rx));

        let (secret_key, public_key) = keypair::generate_keypair(KeyType::Secp256k1);
        let final_hash = [0u8; 32];
        let signature = secret_key.sign(final_hash).unwrap();
        let proof = secret_key.prove(b"test").unwrap();

        let peer_id = PeerId::random();
        let mut members = HashMap::new();
        members.insert(peer_id, (public_key.clone(), proof.clone()));

        let message = Message {
            message_id: MessageId::new(b"test"),
            source: peer_id,
            topic: TEST_INTERNAL_TOPIC.to_string(),
            payload: Payload::ConsensusProposalResult {
                signature: signature.clone(),
            },
            committee_signature: None,
        };

        tokio::spawn(async move {
            tx.send(message).await.unwrap();
        });

        let config = create_test_config();
        let pool = ProposalPool::new(Arc::new(transport), secret_key, config);

        let result = pool.collect_signatures(final_hash, members).await;

        assert!(result.is_ok());
        let signatures = result.unwrap();
        assert_eq!(signatures.len(), 1);
        assert!(signatures.contains_key(&public_key));
    }

    #[tokio::test]
    async fn consensus_result_complete_flow() {
        let mut transport = MockTransport::default();
        let (secret_key, public_key) = keypair::generate_keypair(KeyType::Secp256k1);
        let proof = secret_key.prove(b"test").unwrap();

        // Setup expectations for publish_signature
        transport
            .expect_publish()
            .times(1)
            .returning(|_, _| Ok(MessageId::new(b"test_id")));

        // Setup expectations for collect_signatures
        let (tx, rx) = mpsc::channel(10);
        transport
            .expect_listen_on_topic()
            .times(1)
            .return_once(move |_| Ok(rx));

        // Close channel to simulate no additional signatures
        drop(tx);

        let config = create_test_config();
        let pool = ProposalPool::new(Arc::new(transport), secret_key, config);

        let final_proposals = create_test_hash_set();
        let mut members = HashMap::new();
        members.insert(PeerId::random(), (public_key.clone(), proof));

        let result = pool
            .consensus_result(final_proposals.clone(), members)
            .await;

        assert!(result.is_ok());
        let signed_result = result.unwrap();
        assert_eq!(signed_result.result, final_proposals);
    }
}
