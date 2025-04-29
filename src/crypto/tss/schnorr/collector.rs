use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use tokio::sync::{
    mpsc::{Receiver as TokioReceiver, Sender as TokioSender},
    oneshot::Sender as TokioOneShotSender,
};

use crate::{
    crypto::{
        algebra::{Point, Scalar},
        threshold,
        tss::schnorr::collector::context::Context,
    },
    network::transport::{libp2p_transport::protocols::gossipsub, Transport},
    utils::IndexedMap,
};

mod context;
mod session;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Transport(String),

    #[error("Channel Closed: {0}")]
    ChannelClosed(#[from] tokio::sync::oneshot::error::RecvError),
}

#[derive(Debug)]
enum Command {
    Query {
        id: SessionId,
        immediate_return: bool,
        callback: TokioOneShotSender<CollectionResult>,
    },
    Shutdown,
}

#[derive(Debug)]
pub enum CollectionResult {
    Success(HashMap<libp2p::PeerId, Scalar>),
    Failure(HashSet<libp2p::PeerId>),
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Hash)]
#[derive(PartialEq, Eq)]
enum SessionId {
    NonceShare(Vec<u8>),
    SignatureShare(Vec<u8>),
}

#[derive(Debug)]
pub struct Config {
    pub threshold_counter: threshold::Counter,
    pub topic: String,
    pub timeout: tokio::time::Duration,
}

pub struct Collector<T: Transport + 'static> {
    transport: Arc<T>,
    action_tx: Option<TokioSender<Command>>,
    config: Config,
}

impl<T: Transport + 'static> Collector<T> {
    pub fn new(transport: Arc<T>, config: Config) -> Self {
        Self {
            transport,
            action_tx: None,
            config,
        }
    }

    pub async fn start(
        &mut self,
        partial_pks: IndexedMap<libp2p::PeerId, Vec<Point>>,
    ) -> Result<()> {
        let topic_rx = self
            .transport
            .listen_on_topic(&self.config.topic)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;

        let (action_tx, action_rx) = tokio::sync::mpsc::channel(100);
        self.action_tx = Some(action_tx);

        let threshold = self.config.threshold_counter.call(partial_pks.len()) - 1;
        let ctx = Context::new(threshold, partial_pks);

        tokio::spawn(async move {
            Self::run(ctx, topic_rx, action_rx).await;
        });

        Ok(())
    }

    async fn run(
        ctx: Context,
        mut topic_rx: TokioReceiver<gossipsub::Message>,
        mut action_rx: TokioReceiver<Command>,
    ) {
        const CLEANUP_INTERVAL: tokio::time::Duration = tokio::time::Duration::from_secs(5);

        let mut cleanup_timer = tokio::time::interval(CLEANUP_INTERVAL);

        loop {
            tokio::select! {
                Some(message) = topic_rx.recv() => {
                    Self::process_message(&ctx, message);
                }
                Some(action) = action_rx.recv() => {
                    match action {
                        Command::Query { id, immediate_return, callback } => {
                            Self::process_query_shares(&ctx, id, immediate_return, callback);
                        }
                        Command::Shutdown => {
                            log::info!("Shutting down collector");
                            break;
                        }
                    }
                }
                _ = cleanup_timer.tick() => {
                    ctx.cleanup_completed_sessions();
                }
            }
        }

        log::info!("Collector stopped");
    }

    fn process_message(ctx: &Context, message: gossipsub::Message) {
        match message.payload {
            gossipsub::Payload::TssNonceShare { id, share } => {
                let id = SessionId::NonceShare(id);
                let peer_id = message.source;
                ctx.add_share(id, peer_id, share);
            }
            gossipsub::Payload::TssSignatureShare { id, share } => {
                let id = SessionId::SignatureShare(id);
                let peer_id = message.source;
                ctx.add_share(id, peer_id, share);
            }
            _ => {}
        }
    }

    fn process_query_shares(
        ctx: &Context,
        id: SessionId,
        immediate_return: bool,
        callback: TokioOneShotSender<CollectionResult>,
    ) {
        if immediate_return {
            ctx.force_completion(id, callback);
        } else {
            ctx.register_callback(id, callback);
        }
    }

    pub async fn stop(&mut self) {
        if let Some(action_tx) = self.action_tx.take() {
            let _ = action_tx.send(Command::Shutdown).await;
        }
    }

    async fn query_with_timeout(&self, id: SessionId) -> Result<Option<CollectionResult>> {
        let action_tx = self.action_tx.as_ref().expect("Collector is not started");

        let (callback_tx, callback_rx) = tokio::sync::oneshot::channel();
        let command = Command::Query {
            id: id.clone(),
            immediate_return: false,
            callback: callback_tx,
        };
        action_tx
            .send(command)
            .await
            .expect("Failed to send command");

        match tokio::time::timeout(self.config.timeout, callback_rx).await {
            // Result<Result<CollectionResult, RecvError>, Elapsed>
            Ok(result) => Ok(Some(result?)),
            Err(e) => {
                log::warn!("Timeout while waiting for nonce shares: {:?}", e);
                Ok(None)
            }
        }
    }

    async fn query_with_force(&self, id: SessionId) -> CollectionResult {
        let action_tx = self.action_tx.as_ref().expect("Collector is not started");

        let (callback_tx, callback_rx) = tokio::sync::oneshot::channel();
        let command = Command::Query {
            id: id.clone(),
            immediate_return: true,
            callback: callback_tx,
        };
        action_tx
            .send(command)
            .await
            .expect("Failed to send command");

        match callback_rx.await {
            Ok(result) => result,
            Err(e) => {
                panic!("Failed to receive callback: {:?}", e);
            }
        }
    }

    pub async fn query_signature_share(&self, id: Vec<u8>) -> Result<CollectionResult> {
        let id = SessionId::SignatureShare(id);
        if let Some(result) = self.query_with_timeout(id.clone()).await? {
            Ok(result)
        } else {
            return Ok(self.query_with_force(id).await);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use mockall::predicate::eq;

    use crate::{
        crypto::{
            algebra::{Point, Scheme},
            threshold,
            tss::schnorr::collector::{CollectionResult, Collector, Config, Error},
            vss::Vss,
        },
        mocks::MockError,
        network::transport::MockTransport,
        utils::IndexedMap,
    };

    const TOPIC: &str = "test_topic";
    const TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_millis(100);
    const SCHEME: Scheme = Scheme::Secp256k1;
    const NUM_PEERS: u16 = 3;
    const ID: [u8; 3] = [1, 2, 3];

    fn create_config() -> Config {
        Config {
            threshold_counter: threshold::Counter::default(),
            topic: TOPIC.to_string(),
            timeout: TIMEOUT,
        }
    }

    fn generate_peers(n: u16) -> IndexedMap<libp2p::PeerId, Vec<Point>> {
        let threshold = threshold::Counter::default().call(n);
        let mut peer_ids = generate_peer_ids(n);
        peer_ids.sort();

        peer_ids
            .into_iter()
            .map(|peer_id| {
                let (_, comms) = Vss::share(&SCHEME, threshold - 1, n);
                (peer_id, comms)
            })
            .collect()
    }

    fn generate_peer_ids(n: u16) -> Vec<libp2p::PeerId> {
        (0..n).map(|_| libp2p::PeerId::random()).collect()
    }

    #[tokio::test]
    async fn strat_initialize_successfully() {
        let mut transport = MockTransport::new();
        transport
            .expect_listen_on_topic()
            .with(eq(TOPIC.to_string()))
            .times(1)
            .returning(|_| {
                let (_, rx) = tokio::sync::mpsc::channel(1);
                Ok(rx)
            });
        let transport = Arc::new(transport);
        let config = create_config();
        let mut collector = Collector::new(transport.clone(), config);
        let partial_pks = generate_peers(NUM_PEERS);

        let result = collector.start(partial_pks).await;

        assert!(result.is_ok());
        assert!(collector.action_tx.is_some());

        collector.stop().await;
    }

    #[tokio::test]
    async fn start_fails_on_transport_error() {
        let mut transport = MockTransport::new();
        transport
            .expect_listen_on_topic()
            .with(eq(TOPIC.to_string()))
            .times(1)
            .returning(|_| Err(MockError));

        let transport = Arc::new(transport);
        let config = create_config();
        let mut collector = Collector::new(transport.clone(), config);
        let partial_pks = generate_peers(NUM_PEERS);

        let result = collector.start(partial_pks).await;

        assert!(matches!(result, Err(Error::Transport(_))));
    }

    #[tokio::test]
    async fn query_signature_return_none_on_timeout() {
        let mut transport = MockTransport::new();
        transport
            .expect_listen_on_topic()
            .with(eq(TOPIC.to_string()))
            .times(1)
            .returning(|_| {
                let (_, rx) = tokio::sync::mpsc::channel(1);
                Ok(rx)
            });

        let transport = Arc::new(transport);
        let config = create_config();
        let mut collector = Collector::new(transport.clone(), config);
        let partial_pks = generate_peers(NUM_PEERS);

        collector.start(partial_pks).await.unwrap();

        let result = collector.query_signature_share(ID.to_vec()).await;

        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), CollectionResult::Failure(_)));

        collector.stop().await;
    }

    #[tokio::test]
    async fn stop_shuts_down_collector() {
        let mut transport = MockTransport::new();
        transport
            .expect_listen_on_topic()
            .with(eq(TOPIC.to_string()))
            .times(1)
            .returning(|_| {
                let (_, rx) = tokio::sync::mpsc::channel(1);
                Ok(rx)
            });

        let transport = Arc::new(transport);
        let config = create_config();
        let mut collector = Collector::new(transport.clone(), config);
        let partial_pks = generate_peers(NUM_PEERS);

        collector.start(partial_pks).await.unwrap();

        collector.stop().await;

        assert!(collector.action_tx.is_none());
    }
}
