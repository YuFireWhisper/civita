use std::{collections::HashMap, marker::PhantomData, sync::Arc};

use libp2p::PeerId;
use serde::{Deserialize, Serialize};

use crate::{
    constants::HashArray,
    network::transport::{
        self,
        protocols::gossipsub,
        store::merkle_dag::{self, KeyArray, Node},
    },
    proposal::{
        collector::{self, Collector, Context},
        vrf_elector, Proposal,
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

    #[error("{0}")]
    Proposal(String),
}

#[derive(Clone)]
#[derive(Debug)]
pub struct Config {
    pub external_topic: String,
    pub num_proposals_per_batch: usize,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Default)]
#[derive(Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
pub struct RecordBatch {
    pub records: Vec<(KeyArray, Record)>,
    pub total_stakes_impact: i32,
}

#[derive(Clone)]
struct ProposalContext<P> {
    transport: Arc<Transport>,
    batches: Vec<RecordBatch>,
    root: Node,
    num_proposals_per_batch: usize,
    _marker: PhantomData<P>,
}

pub struct Pool<P: Proposal> {
    transport: Arc<Transport>,
    collector: Collector<ProposalContext<P>>,
    config: Config,
}

impl<P: Proposal> ProposalContext<P> {
    pub fn new(
        transport: Arc<Transport>,
        root: Node,
        batches: Vec<RecordBatch>,
        num_proposals_per_batch: usize,
    ) -> Self {
        Self {
            transport,
            batches,
            root,
            num_proposals_per_batch,
            _marker: PhantomData,
        }
    }

    async fn add_proposal(&mut self, slice: &[u8]) -> Result<()> {
        let proposal =
            P::from_slice(slice).map_err(|e| Error::ProposalSerialization(e.to_string()))?;

        let resident_keys = proposal
            .impact()
            .map_err(|e| Error::Proposal(e.to_string()))?;
        let impacted_residents = self.get_impacted_residents(resident_keys.clone()).await?;

        let mut records: HashMap<_, _> =
            resident_keys.into_iter().zip(impacted_residents).collect();

        if !proposal
            .verify(&records)
            .map_err(|e| Error::Proposal(e.to_string()))?
        {
            log::warn!("Proposal verification failed");
            return Ok(());
        }

        proposal
            .apply(&mut records)
            .map_err(|e| Error::Proposal(e.to_string()))?;

        let impact_stakes = proposal
            .impact_stakes()
            .map_err(|e| Error::Proposal(e.to_string()))?;

        if self.batches.is_empty()
            || self.batches.last().unwrap().records.len() >= self.num_proposals_per_batch
        {
            self.batches.push(RecordBatch::default());
        }

        let last_batch = self.batches.last_mut().unwrap();

        last_batch.total_stakes_impact += impact_stakes;
        last_batch
            .records
            .extend(records.into_iter().map(|(k, v)| (hash_to_key_array(k), v)));

        Ok(())
    }

    async fn get_impacted_residents(&self, hashes: Vec<HashArray>) -> Result<Vec<Record>> {
        let keys: Vec<KeyArray> = hashes.into_iter().map(hash_to_key_array).collect();

        let hashes = self.root.batch_get(keys, &self.transport).await?;

        let futures = hashes
            .into_iter()
            .map(|hash_opt| async move {
                if let Some(hash) = hash_opt {
                    self.transport.get::<Record>(&hash).await
                } else {
                    Ok(Some(Record::default()))
                }
            })
            .collect::<Vec<_>>();

        let results = futures::future::join_all(futures)
            .await
            .into_iter()
            .map(|res| match res {
                Ok(Some(record)) => Ok(record),
                Ok(None) => Ok(Record::default()),
                Err(e) => Err(Error::from(e)),
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(results)
    }
}

impl<P: Proposal> Pool<P> {
    pub fn new(transport: Arc<Transport>, config: Config) -> Self {
        Self {
            transport,
            collector: Collector::new(),
            config,
        }
    }

    pub async fn start(&self, root: Node, per_batches: Vec<RecordBatch>) -> Result<()> {
        let ctx = ProposalContext::<P>::new(
            self.transport.clone(),
            root,
            per_batches,
            self.config.num_proposals_per_batch,
        );
        let rx = self
            .transport
            .listen_on_topic(&self.config.external_topic)
            .await?;
        self.collector.start(rx, ctx).await;
        Ok(())
    }

    pub async fn stop(&self) -> Result<Vec<RecordBatch>> {
        let ctx = self.collector.stop().await?;
        Ok(ctx.batches)
    }
}

pub fn hash_to_key_array(hash: HashArray) -> KeyArray {
    unsafe { std::mem::transmute(hash) }
}

pub fn key_to_hash_array(key: KeyArray) -> HashArray {
    unsafe { std::mem::transmute(key) }
}

#[async_trait::async_trait]
impl<P: Proposal> Context for ProposalContext<P> {
    async fn handle_message(&mut self, msg: gossipsub::Message) {
        if let gossipsub::Payload::Proposal(data) = msg.payload {
            if let Err(e) = self.add_proposal(&data).await {
                log::warn!("Failed to add proposal: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use libp2p::{gossipsub::MessageId, PeerId};
    use mockall::predicate::*;
    use tokio::sync::mpsc;

    use super::*;
    use crate::{
        mocks::MockError,
        network::transport::{
            protocols::gossipsub::{self, Payload},
            MockTransport,
        },
        proposal::{MockProposal, __mock_MockProposal_Proposal::__from_slice},
        resident::Record,
    };

    const TEST_TOPIC: &str = "test_topic";
    const NUM_PROPOSALS_PER_BATCH: usize = 3;
    const TEST_STAKE_IMPACT: i32 = 100;

    static MIT: Mutex<()> = Mutex::new(());

    struct TestFixture {
        transport: Arc<MockTransport>,
        config: Config,
        root: Node,
        record: Record,
        hash: HashArray,
        key_array: KeyArray,
    }

    impl TestFixture {
        fn new() -> Self {
            Self {
                transport: Arc::new(MockTransport::default()),
                config: Config {
                    external_topic: TEST_TOPIC.to_string(),
                    num_proposals_per_batch: NUM_PROPOSALS_PER_BATCH,
                },
                root: Node::new(),
                record: Record::default(),
                hash: [1u8; 32],
                key_array: [1u16; 16],
            }
        }

        fn create_record_batch(&self) -> RecordBatch {
            RecordBatch {
                records: vec![(self.key_array, self.record.clone())],
                total_stakes_impact: TEST_STAKE_IMPACT,
            }
        }

        fn create_gossipsub_message(&self, payload: Payload) -> gossipsub::Message {
            gossipsub::Message {
                message_id: MessageId::new(b"test_message_id"),
                source: PeerId::random(),
                topic: TEST_TOPIC.to_string(),
                payload,
                committee_signature: None,
            }
        }

        fn create_proposal_context(&self) -> ProposalContext<MockProposal> {
            ProposalContext::<MockProposal>::new(
                self.transport.clone(),
                self.root.clone(),
                vec![],
                NUM_PROPOSALS_PER_BATCH,
            )
        }

        fn setup_successful_transport(&mut self) {
            let record = self.record.clone();
            Arc::get_mut(&mut self.transport)
                .unwrap()
                .expect_get::<Record>()
                .returning(move |_| Ok(Some(record.clone())));
        }

        fn setup_transport_listen_success(&mut self) {
            Arc::get_mut(&mut self.transport)
                .unwrap()
                .expect_listen_on_topic()
                .with(eq(TEST_TOPIC))
                .times(1)
                .returning(|_| Ok(mpsc::channel(10).1));
        }

        fn setup_transport_listen_error(&mut self) {
            Arc::get_mut(&mut self.transport)
                .unwrap()
                .expect_listen_on_topic()
                .with(eq(TEST_TOPIC))
                .times(1)
                .returning(|_| Err(transport::Error::MockError));
        }

        fn setup_transport_get_none(&mut self) {
            Arc::get_mut(&mut self.transport)
                .unwrap()
                .expect_get::<Record>()
                .returning(|_| Ok(None));
        }
    }

    fn setup_successful_proposal_mock() -> __from_slice::Context {
        let ctx = MockProposal::from_slice_context();
        ctx.expect().returning(|_| {
            let mut mock_proposal = MockProposal::new();
            let test_hash = [1u8; 32];

            mock_proposal
                .expect_impact()
                .returning(move || Ok(vec![test_hash]));
            mock_proposal.expect_verify().returning(|_| Ok(true));
            mock_proposal.expect_apply().returning(|_| Ok(()));
            mock_proposal
                .expect_impact_stakes()
                .returning(|| Ok(TEST_STAKE_IMPACT));

            Ok(mock_proposal)
        });
        ctx
    }

    fn setup_failing_proposal_mock() -> __from_slice::Context {
        let ctx = MockProposal::from_slice_context();
        ctx.expect().returning(|_| Err(MockError));
        ctx
    }

    fn setup_verification_failing_proposal_mock() -> __from_slice::Context {
        let ctx = MockProposal::from_slice_context();
        ctx.expect().returning(|_| {
            let mut mock_proposal = MockProposal::new();
            let test_hash = [1u8; 32];

            mock_proposal
                .expect_impact()
                .returning(move || Ok(vec![test_hash]));
            mock_proposal.expect_verify().returning(|_| Ok(false));
            mock_proposal.expect_apply().returning(|_| Ok(()));
            mock_proposal
                .expect_impact_stakes()
                .returning(|| Ok(TEST_STAKE_IMPACT));

            Ok(mock_proposal)
        });
        ctx
    }

    #[tokio::test]
    async fn pool_creation() {
        let fixture = TestFixture::new();
        let pool = Pool::<MockProposal>::new(fixture.transport, fixture.config.clone());

        assert_eq!(pool.config.external_topic, fixture.config.external_topic);
        assert_eq!(
            pool.config.num_proposals_per_batch,
            fixture.config.num_proposals_per_batch
        );
    }

    #[tokio::test]
    async fn start_pool_success() {
        let mut fixture = TestFixture::new();
        fixture.setup_transport_listen_success();

        let pool = Pool::<MockProposal>::new(fixture.transport.clone(), fixture.config.clone());
        let batches = vec![fixture.create_record_batch()];

        let result = pool.start(fixture.root, batches).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn start_pool_transport_error() {
        let mut fixture = TestFixture::new();
        fixture.setup_transport_listen_error();

        let pool = Pool::<MockProposal>::new(fixture.transport, fixture.config);

        let result = pool.start(fixture.root, vec![]).await;
        assert!(matches!(result, Err(Error::Transport(_))));
    }

    #[tokio::test]
    async fn add_proposal_success() {
        let _m = MIT.lock();

        let mut fixture = TestFixture::new();
        fixture.setup_successful_transport();

        let _ctx = setup_successful_proposal_mock();

        let mut ctx = fixture.create_proposal_context();
        let result = ctx.add_proposal(b"test_proposal_data").await;

        assert!(result.is_ok());
        assert_eq!(ctx.batches.len(), 1);
        assert_eq!(ctx.batches[0].total_stakes_impact, TEST_STAKE_IMPACT);
    }

    #[tokio::test]
    async fn add_proposal_serialization_error() {
        let _m = MIT.lock();

        let fixture = TestFixture::new();
        let _ctx = setup_failing_proposal_mock();

        let mut ctx = fixture.create_proposal_context();
        let result = ctx.add_proposal(b"invalid_data").await;

        assert!(matches!(result, Err(Error::ProposalSerialization(_))));
    }

    #[tokio::test]
    async fn add_proposal_verification_failure() {
        let _m = MIT.lock();

        let fixture = TestFixture::new();
        let _ctx = setup_verification_failing_proposal_mock();

        let mut ctx = fixture.create_proposal_context();
        let result = ctx.add_proposal(b"test_data").await;

        assert!(result.is_ok());
        assert_eq!(ctx.batches.len(), 0);
    }

    #[tokio::test]
    async fn add_proposal_multiple_batches() {
        let _m = MIT.lock();

        let mut fixture = TestFixture::new();
        fixture.setup_successful_transport();

        let mut ctx = ProposalContext::<MockProposal>::new(
            fixture.transport.clone(),
            fixture.root.clone(),
            vec![],
            1,
        );

        for i in 0..3 {
            let _ctx = setup_successful_proposal_mock();
            let result = ctx.add_proposal(&[i as u8]).await;
            assert!(result.is_ok());
        }

        assert_eq!(ctx.batches.len(), 3);
    }

    #[tokio::test]
    async fn get_impacted_residents_success() {
        let mut fixture = TestFixture::new();
        fixture.setup_successful_transport();

        let ctx = fixture.create_proposal_context();
        let result = ctx.get_impacted_residents(vec![fixture.hash]).await;

        assert!(result.is_ok());
        let residents = result.unwrap();
        assert_eq!(residents.len(), 1);
    }

    #[tokio::test]
    async fn get_impacted_residents_not_found() {
        let mut fixture = TestFixture::new();
        fixture.setup_transport_get_none();

        let ctx = fixture.create_proposal_context();
        let result = ctx.get_impacted_residents(vec![fixture.hash]).await;

        assert!(result.is_ok());
        let residents = result.unwrap();
        assert_eq!(residents.len(), 1);
        assert_eq!(residents[0], Record::default());
    }

    #[tokio::test]
    async fn handle_message_proposal_payload() {
        let _m = MIT.lock();

        let mut fixture = TestFixture::new();
        fixture.setup_successful_transport();
        let _ctx = setup_successful_proposal_mock();

        let mut ctx = fixture.create_proposal_context();
        let payload = Payload::Proposal(b"test_proposal".to_vec());
        let message = fixture.create_gossipsub_message(payload);

        ctx.handle_message(message).await;

        assert_eq!(ctx.batches.len(), 1);
        assert_eq!(ctx.batches[0].total_stakes_impact, TEST_STAKE_IMPACT);
    }

    #[tokio::test]
    async fn empty_proposal_data() {
        let _m = MIT.lock();

        let fixture = TestFixture::new();
        let _ctx = setup_failing_proposal_mock();

        let mut ctx = fixture.create_proposal_context();
        let result = ctx.add_proposal(&[]).await;

        assert!(matches!(result, Err(Error::ProposalSerialization(_))));
    }

    #[tokio::test]
    async fn concurrent_proposal_handling() {
        let _m = MIT.lock();

        let mut fixture = TestFixture::new();
        fixture.setup_successful_transport();

        let ctx = Arc::new(tokio::sync::Mutex::new(fixture.create_proposal_context()));
        let mut handles = vec![];

        for i in 0..5 {
            let ctx_clone = ctx.clone();
            let handle = tokio::spawn(async move {
                let _ctx = setup_successful_proposal_mock();
                let mut ctx_guard = ctx_clone.lock().await;
                ctx_guard.add_proposal(&[i as u8]).await
            });
            handles.push(handle);
        }

        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok());
        }
    }

    #[test]
    fn hash_to_key_array_conversion() {
        let fixture = TestFixture::new();
        let key_array = hash_to_key_array(fixture.hash);
        let converted_back = key_to_hash_array(key_array);

        assert_eq!(fixture.hash, converted_back);
    }

    #[test]
    fn key_to_hash_array_conversion() {
        let fixture = TestFixture::new();
        let hash = key_to_hash_array(fixture.key_array);
        let converted_back = hash_to_key_array(hash);

        assert_eq!(fixture.key_array, converted_back);
    }

    #[test]
    fn record_batch_default() {
        let batch = RecordBatch::default();
        assert!(batch.records.is_empty());
        assert_eq!(batch.total_stakes_impact, 0);
    }

    #[test]
    fn record_batch_equality() {
        let fixture = TestFixture::new();
        let batch1 = fixture.create_record_batch();
        let batch2 = fixture.create_record_batch();
        assert_eq!(batch1, batch2);
    }

    #[test]
    fn record_batch_clone() {
        let fixture = TestFixture::new();
        let batch1 = fixture.create_record_batch();
        let batch2 = batch1.clone();
        assert_eq!(batch1, batch2);
    }

    #[test]
    fn config_clone() {
        let fixture = TestFixture::new();
        let config2 = fixture.config.clone();
        assert_eq!(fixture.config.external_topic, config2.external_topic);
        assert_eq!(
            fixture.config.num_proposals_per_batch,
            config2.num_proposals_per_batch
        );
    }
}
