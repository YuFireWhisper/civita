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
        index_map::IndexedMap,
        primitives::{
            algebra::{Point, Scalar},
            threshold,
        },
        tss::schnorr::collector::context::Context,
    },
    network::transport::{libp2p_transport::protocols::gossipsub, Transport},
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

        let threshold = self.config.threshold_counter.call(partial_pks.len()) - 1; // Exclude self
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
                            Self::process_query_nonce_shares(&ctx, id, immediate_return, callback);
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
        if let gossipsub::Payload::TssNonceShare { id, share } = message.payload {
            let id = SessionId::NonceShare(id);
            let peer_id = message.source;
            ctx.add_share(id, peer_id, share);
        }
    }

    fn process_query_nonce_shares(
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

    pub async fn query_nonce_shares(&self, id: Vec<u8>) -> Result<CollectionResult> {
        let id = SessionId::NonceShare(id);
        if let Some(result) = self.query_with_timeout(id.clone()).await? {
            Ok(result)
        } else {
            return Ok(self.query_with_force(id).await);
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
