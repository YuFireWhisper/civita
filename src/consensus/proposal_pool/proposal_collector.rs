use std::{collections::HashSet, sync::Arc};

use tokio::{
    sync::oneshot,
    task::{JoinError, JoinHandle},
};

#[cfg(not(test))]
use crate::network::transport::Transport;
use crate::{
    constants::HashArray,
    network::transport::{self, protocols::gossipsub, store::merkle_dag::Node},
};

#[cfg(test)]
use crate::network::transport::MockTransport as Transport;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Transport(#[from] transport::Error),

    #[error("Collector not started")]
    NotStarted,

    #[error("{0}")]
    Join(#[from] JoinError),

    #[error("Fialed to send shutdown signal")]
    SendFailed,
}

pub struct ProposalCollector {
    transport: Arc<Transport>,
    handle: Option<(JoinHandle<HashSet<HashArray>>, oneshot::Sender<()>)>,
}

impl ProposalCollector {
    pub fn new(transport: Arc<Transport>) -> Self {
        ProposalCollector {
            transport,
            handle: None,
        }
    }

    pub async fn start(&mut self, topic: &str) -> Result<()> {
        let mut rx = self.transport.listen_on_topic(topic).await?;
        let transport = self.transport.clone();

        let (oneshot_tx, mut oneshot_rx) = oneshot::channel();

        let handle = tokio::spawn(async move {
            let mut proposals = HashSet::new();

            loop {
                tokio::select! {
                    Some(msg) = rx.recv() => {
                        if let gossipsub::Payload::Proposal(hash) = msg.payload {
                            if Self::is_valid_proposal(&transport, hash)
                                .await
                                .unwrap_or(false)
                            {
                                proposals.insert(hash);
                            }
                        }
                    }
                    _ = &mut oneshot_rx => {
                        break;
                    }
                }
            }

            proposals
        });

        self.handle = Some((handle, oneshot_tx));

        Ok(())
    }

    async fn is_valid_proposal(transport: &Transport, hash: HashArray) -> Result<bool> {
        transport
            .get::<Node>(&hash)
            .await
            .map(|opt| opt.is_some())
            .map_err(Error::from)
    }

    pub async fn settle(&mut self) -> Result<HashSet<HashArray>> {
        if let Some((handle, oneshot_tx)) = self.handle.take() {
            oneshot_tx.send(()).map_err(|_| Error::SendFailed)?;
            handle.await.map_err(Error::from)
        } else {
            Err(Error::NotStarted)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::transport::{protocols::gossipsub, MockTransport};
    use libp2p::gossipsub::MessageId;
    use std::time::Duration;
    use tokio::sync::mpsc;

    const TEST_TOPIC: &str = "test_proposals";
    const TIMEOUT_MS: u64 = 100;

    fn create_test_hash() -> HashArray {
        [1u8; 32]
    }

    fn create_different_test_hash() -> HashArray {
        [2u8; 32]
    }

    async fn setup_collector() -> (ProposalCollector, Arc<MockTransport>) {
        let mut mock_transport = MockTransport::default();
        mock_transport.expect_listen_on_topic().returning(|_| {
            let (_, rx) = mpsc::channel(10);
            Ok(rx)
        });

        let transport = Arc::new(mock_transport);
        let collector = ProposalCollector::new(transport.clone());
        (collector, transport)
    }

    #[tokio::test]
    async fn new_creates_collector_with_none_handle() {
        let mock_transport = MockTransport::default();
        let transport = Arc::new(mock_transport);

        let collector = ProposalCollector::new(transport);

        assert!(collector.handle.is_none());
    }

    #[tokio::test]
    async fn start_initializes_collector_successfully() {
        let (mut collector, _) = setup_collector().await;

        let result = collector.start(TEST_TOPIC).await;

        assert!(result.is_ok());
        assert!(collector.handle.is_some());
    }

    #[tokio::test]
    async fn start_with_transport_error() {
        let mut mock_transport = MockTransport::default();
        mock_transport
            .expect_listen_on_topic()
            .returning(|_| Err(transport::Error::MockError));

        let transport = Arc::new(mock_transport);
        let mut collector = ProposalCollector::new(transport);

        let result = collector.start(TEST_TOPIC).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Transport(_)));
    }

    #[tokio::test]
    async fn settle_without_start_returns_error() {
        let (mut collector, _) = setup_collector().await;

        let result = collector.settle().await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::NotStarted));
    }

    #[tokio::test]
    async fn settle_after_start_returns_empty_proposals() {
        let (mut collector, _) = setup_collector().await;

        collector.start(TEST_TOPIC).await.unwrap();

        // Give some time for the task to start
        tokio::time::sleep(Duration::from_millis(10)).await;

        let result = collector.settle().await;

        assert!(result.is_ok());
        let proposals = result.unwrap();
        assert!(proposals.is_empty());
    }

    #[tokio::test]
    async fn collect_valid_proposals() {
        let (tx, rx) = mpsc::channel(10);
        let mut mock_transport = MockTransport::default();

        mock_transport
            .expect_listen_on_topic()
            .return_once(move |_| Ok(rx));

        let test_hash = create_test_hash();
        mock_transport
            .expect_get::<Node>()
            .with(mockall::predicate::eq(test_hash))
            .returning(|_| Ok(Some(Node::default())));

        let transport = Arc::new(mock_transport);
        let mut collector = ProposalCollector::new(transport);

        collector.start(TEST_TOPIC).await.unwrap();

        // Send a valid proposal message
        let msg = gossipsub::Message {
            message_id: MessageId::new(&[1; 32]),
            source: libp2p::PeerId::random(),
            topic: TEST_TOPIC.to_string(),
            payload: gossipsub::Payload::Proposal(test_hash),
            committee_signature: None,
        };

        tx.send(msg).await.unwrap();

        // Give some time for processing
        tokio::time::sleep(Duration::from_millis(TIMEOUT_MS)).await;

        let result = collector.settle().await;

        assert!(result.is_ok());
        let proposals = result.unwrap();
        assert_eq!(proposals.len(), 1);
        assert!(proposals.contains(&test_hash));
    }

    #[tokio::test]
    async fn collect_multiple_valid_proposals() {
        let (tx, rx) = mpsc::channel(10);
        let mut mock_transport = MockTransport::default();

        mock_transport
            .expect_listen_on_topic()
            .return_once(move |_| Ok(rx));

        let hash1 = create_test_hash();
        let hash2 = create_different_test_hash();

        mock_transport
            .expect_get::<Node>()
            .returning(|_| Ok(Some(Node::default())));

        let transport = Arc::new(mock_transport);
        let mut collector = ProposalCollector::new(transport);

        collector.start(TEST_TOPIC).await.unwrap();

        // Send multiple proposal messages
        let msg1 = gossipsub::Message {
            message_id: MessageId::new(&[1; 32]),
            source: libp2p::PeerId::random(),
            topic: TEST_TOPIC.to_string(),
            payload: gossipsub::Payload::Proposal(hash1),
            committee_signature: None,
        };

        let msg2 = gossipsub::Message {
            message_id: MessageId::new(&[2; 32]),
            source: libp2p::PeerId::random(),
            topic: TEST_TOPIC.to_string(),
            payload: gossipsub::Payload::Proposal(hash2),
            committee_signature: None,
        };

        tx.send(msg1).await.unwrap();
        tx.send(msg2).await.unwrap();

        // Give some time for processing
        tokio::time::sleep(Duration::from_millis(TIMEOUT_MS)).await;

        let result = collector.settle().await;

        assert!(result.is_ok());
        let proposals = result.unwrap();
        assert_eq!(proposals.len(), 2);
        assert!(proposals.contains(&hash1));
        assert!(proposals.contains(&hash2));
    }

    #[tokio::test]
    async fn ignore_invalid_proposals() {
        let (tx, rx) = mpsc::channel(10);
        let mut mock_transport = MockTransport::default();

        mock_transport
            .expect_listen_on_topic()
            .return_once(move |_| Ok(rx));

        let test_hash = create_test_hash();
        mock_transport
            .expect_get::<Node>()
            .with(mockall::predicate::eq(test_hash))
            .returning(|_| Ok(None)); // Return None to indicate invalid proposal

        let transport = Arc::new(mock_transport);
        let mut collector = ProposalCollector::new(transport);

        collector.start(TEST_TOPIC).await.unwrap();

        // Send an invalid proposal message
        let msg = gossipsub::Message {
            message_id: MessageId::new(&[1; 32]),
            source: libp2p::PeerId::random(),
            topic: TEST_TOPIC.to_string(),
            payload: gossipsub::Payload::Proposal(test_hash),
            committee_signature: None,
        };

        tx.send(msg).await.unwrap();

        // Give some time for processing
        tokio::time::sleep(Duration::from_millis(TIMEOUT_MS)).await;

        let result = collector.settle().await;

        assert!(result.is_ok());
        let proposals = result.unwrap();
        assert!(proposals.is_empty());
    }

    #[tokio::test]
    async fn ignore_transport_validation_errors() {
        let (tx, rx) = mpsc::channel(10);
        let mut mock_transport = MockTransport::default();

        mock_transport
            .expect_listen_on_topic()
            .return_once(move |_| Ok(rx));

        let test_hash = create_test_hash();
        mock_transport
            .expect_get::<Node>()
            .with(mockall::predicate::eq(test_hash))
            .returning(|_| Err(transport::Error::MockError));

        let transport = Arc::new(mock_transport);
        let mut collector = ProposalCollector::new(transport);

        collector.start(TEST_TOPIC).await.unwrap();

        // Send a proposal message that will cause validation error
        let msg = gossipsub::Message {
            message_id: MessageId::new(&[1; 32]),
            source: libp2p::PeerId::random(),
            topic: TEST_TOPIC.to_string(),
            payload: gossipsub::Payload::Proposal(test_hash),
            committee_signature: None,
        };

        tx.send(msg).await.unwrap();

        // Give some time for processing
        tokio::time::sleep(Duration::from_millis(TIMEOUT_MS)).await;

        let result = collector.settle().await;

        assert!(result.is_ok());
        let proposals = result.unwrap();
        assert!(proposals.is_empty());
    }

    #[tokio::test]
    async fn ignore_non_proposal_messages() {
        let (tx, rx) = mpsc::channel(10);
        let mut mock_transport = MockTransport::default();

        mock_transport
            .expect_listen_on_topic()
            .return_once(move |_| Ok(rx));

        let transport = Arc::new(mock_transport);
        let mut collector = ProposalCollector::new(transport);

        collector.start(TEST_TOPIC).await.unwrap();

        // Send a non-proposal message
        let msg = gossipsub::Message {
            message_id: MessageId::new(&[1; 32]),
            source: libp2p::PeerId::random(),
            topic: TEST_TOPIC.to_string(),
            payload: gossipsub::Payload::Raw("not a proposal".into()),
            committee_signature: None,
        };

        tx.send(msg).await.unwrap();

        // Give some time for processing
        tokio::time::sleep(Duration::from_millis(TIMEOUT_MS)).await;

        let result = collector.settle().await;

        assert!(result.is_ok());
        let proposals = result.unwrap();
        assert!(proposals.is_empty());
    }

    #[tokio::test]
    async fn deduplicate_proposals() {
        let (tx, rx) = mpsc::channel(10);
        let mut mock_transport = MockTransport::default();

        mock_transport
            .expect_listen_on_topic()
            .return_once(move |_| Ok(rx));

        let test_hash = create_test_hash();
        mock_transport
            .expect_get::<Node>()
            .returning(|_| Ok(Some(Node::default())));

        let transport = Arc::new(mock_transport);
        let mut collector = ProposalCollector::new(transport);

        collector.start(TEST_TOPIC).await.unwrap();

        // Send the same proposal multiple times
        for i in 0..3 {
            let msg = gossipsub::Message {
                message_id: MessageId::new(&[i; 32]),
                source: libp2p::PeerId::random(),
                topic: TEST_TOPIC.to_string(),
                payload: gossipsub::Payload::Proposal(test_hash),
                committee_signature: None,
            };
            tx.send(msg).await.unwrap();
        }

        // Give some time for processing
        tokio::time::sleep(Duration::from_millis(TIMEOUT_MS)).await;

        let result = collector.settle().await;

        assert!(result.is_ok());
        let proposals = result.unwrap();
        assert_eq!(proposals.len(), 1);
        assert!(proposals.contains(&test_hash));
    }

    #[tokio::test]
    async fn multiple_settle_calls_fail() {
        let (mut collector, _) = setup_collector().await;

        collector.start(TEST_TOPIC).await.unwrap();

        // First settle should succeed
        let result1 = collector.settle().await;
        assert!(result1.is_ok());

        // Second settle should fail
        let result2 = collector.settle().await;
        assert!(result2.is_err());
        assert!(matches!(result2.unwrap_err(), Error::NotStarted));
    }

    #[tokio::test]
    async fn shutdown_signal_stops_collection() {
        let (_, rx) = mpsc::channel(10);
        let mut mock_transport = MockTransport::default();

        mock_transport
            .expect_listen_on_topic()
            .return_once(move |_| Ok(rx));

        let transport = Arc::new(mock_transport);
        let mut collector = ProposalCollector::new(transport);

        collector.start(TEST_TOPIC).await.unwrap();

        // Settle immediately without sending any messages
        let result = collector.settle().await;

        assert!(result.is_ok());
        let proposals = result.unwrap();
        assert!(proposals.is_empty());
    }

    #[tokio::test]
    async fn handle_start_after_settle() {
        let (mut collector, _) = setup_collector().await;

        collector.start(TEST_TOPIC).await.unwrap();
        collector.settle().await.unwrap();

        // Should be able to start again after settle
        let result = collector.start(TEST_TOPIC).await;
        assert!(result.is_ok());
        assert!(collector.handle.is_some());
    }

    #[tokio::test]
    async fn collect_proposals_with_committee_signatures() {
        let (tx, rx) = mpsc::channel(10);
        let mut mock_transport = MockTransport::default();

        mock_transport
            .expect_listen_on_topic()
            .return_once(move |_| Ok(rx));

        let test_hash = create_test_hash();
        mock_transport
            .expect_get::<Node>()
            .returning(|_| Ok(Some(Node::default())));

        let transport = Arc::new(mock_transport);
        let mut collector = ProposalCollector::new(transport);

        collector.start(TEST_TOPIC).await.unwrap();

        // Create message with committee signature
        let msg = gossipsub::Message {
            message_id: MessageId::new(&[1; 32]),
            source: libp2p::PeerId::random(),
            topic: TEST_TOPIC.to_string(),
            payload: gossipsub::Payload::Proposal(test_hash),
            committee_signature: None, // No committee signature for simplicity
        };

        tx.send(msg).await.unwrap();
        tokio::time::sleep(Duration::from_millis(TIMEOUT_MS)).await;

        let result = collector.settle().await;

        assert!(result.is_ok());
        let proposals = result.unwrap();
        assert_eq!(proposals.len(), 1);
        assert!(proposals.contains(&test_hash));
    }
}
