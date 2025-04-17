use std::{collections::VecDeque, sync::Arc};

use tokio::sync::{mpsc, oneshot};

use crate::crypto::{
    dkg::joint_feldman::collector::event::ActionNeeded, primitives::vss::DecryptedShares,
};
use crate::{
    crypto::{
        dkg::joint_feldman::{collector::context::Context, peer_registry::PeerRegistry},
        keypair::{self, SecretKey},
        primitives::algebra::{self},
    },
    network::transport::{libp2p_transport::protocols::gossipsub, Transport},
};

pub mod config;
mod context;
pub(super) mod event;

pub use config::Config;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Transport error: {0}")]
    Transport(String),

    #[error("Query error: {0}")]
    Query(String),

    #[error("Context error: {0}")]
    Context(#[from] context::Error),

    #[error("Channel closed")]
    ChannelClosed,

    #[error("Algebra error: {0}")]
    Algebra(#[from] algebra::Error),

    #[error("Share not found")]
    ShareNotFound,

    #[error("Keypair error: {0}")]
    Keypair(#[from] keypair::Error),
}

enum Command {
    Query {
        id: Vec<u8>,
        de_shares: DecryptedShares,
        callback: oneshot::Sender<event::Output>,
    },
    Shutdown,
}

struct Query {
    id: Vec<u8>,
    deadline: tokio::time::Instant,
    callback: oneshot::Sender<event::Output>,
}

struct WorkerContext<T: Transport> {
    context: Context,
    transport: Arc<T>,
    topic: String,
}

pub struct Collector<T: Transport + 'static> {
    transport: Arc<T>,
    secret_key: Arc<SecretKey>,
    config: Config,
    command_tx: Option<mpsc::Sender<Command>>,
    worker_handle: Option<tokio::task::JoinHandle<()>>,
}

impl<T: Transport + 'static> Collector<T> {
    pub fn new(transport: Arc<T>, secret_key: Arc<SecretKey>, config: Config) -> Self {
        Self {
            transport,
            secret_key,
            config,
            command_tx: None,
            worker_handle: None,
        }
    }

    pub async fn start(&mut self, peers: PeerRegistry) -> Result<()> {
        let (command_tx, command_rx) = mpsc::channel(self.config.query_channel_size);
        self.command_tx = Some(command_tx);

        let gossipsub_rx = self
            .transport
            .listen_on_topic(&self.config.gossipsub_topic)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;

        let secret_key = self.secret_key.clone();
        let transport = self.transport.clone();
        let topic = self.config.gossipsub_topic.clone();
        let timeout = self.config.timeout;

        let handle = tokio::spawn(async move {
            let context = Context::new(peers, secret_key, transport.self_peer());
            let worker_ctx = WorkerContext {
                context,
                transport,
                topic,
            };

            Self::run_worker(worker_ctx, command_rx, gossipsub_rx, timeout).await;
        });

        self.worker_handle = Some(handle);
        Ok(())
    }

    async fn run_worker(
        worker_ctx: WorkerContext<T>,
        mut command_rx: mpsc::Receiver<Command>,
        mut gossipsub_rx: mpsc::Receiver<gossipsub::Message>,
        timeout: tokio::time::Duration,
    ) {
        let mut pending_queries = VecDeque::new();
        let mut check_timer = tokio::time::interval(tokio::time::Duration::from_secs(1));

        loop {
            tokio::select! {
                Some(msg) = gossipsub_rx.recv() => {
                    if let Err(e) = Self::process_message(&worker_ctx, msg).await {
                        log::error!("Failed to process message: {}", e);
                    }
                }

                Some(cmd) = command_rx.recv() => {
                    match cmd {
                        Command::Query { id, de_shares, callback } => {
                            if let Err(e) = Self::handle_query(
                                &worker_ctx,
                                id,
                                de_shares,
                                callback,
                                timeout,
                                &mut pending_queries,
                            ).await {
                                log::error!("Failed to handle query: {}", e);
                            }
                        }
                        Command::Shutdown => break,
                    }
                }

                _ = check_timer.tick() => {
                    Self::process_expired_queries(&mut pending_queries, &worker_ctx.context);
                }

                else => break,
            }
        }

        log::info!("Collector worker stopped");
    }

    async fn process_message(worker_ctx: &WorkerContext<T>, msg: gossipsub::Message) -> Result<()> {
        let (action_needed, id) = match msg.payload {
            gossipsub::Payload::VSSComponments {
                id,
                encrypted_shares,
                commitments,
            } => {
                let action_needed = worker_ctx.context.handle_componments(
                    id.clone(),
                    msg.source,
                    encrypted_shares,
                    commitments,
                )?;
                (action_needed, id)
            }
            gossipsub::Payload::VSSReport {
                id,
                decrypted_shares,
            } => {
                let action_needed =
                    worker_ctx
                        .context
                        .handle_report(id.clone(), msg.source, decrypted_shares)?;
                (action_needed, id)
            }
            gossipsub::Payload::VSSReportResponse {
                id,
                decrypted_shares,
            } => {
                let action_needed = worker_ctx.context.handle_report_response(
                    id.clone(),
                    msg.source,
                    decrypted_shares,
                )?;
                (action_needed, id)
            }
            _ => (ActionNeeded::None, vec![]),
        };

        if let ActionNeeded::Report(de_share) = action_needed {
            Self::send_report_response(&worker_ctx.transport, &worker_ctx.topic, id, de_share)
                .await?;
        }

        Ok(())
    }

    async fn send_report_response(
        transport: &Arc<T>,
        topic: &str,
        id: Vec<u8>,
        de_share: DecryptedShares,
    ) -> Result<()> {
        let payload = gossipsub::Payload::VSSReportResponse {
            id,
            decrypted_shares: de_share,
        };

        transport
            .publish(topic, payload)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;

        Ok(())
    }

    async fn handle_query(
        worker_ctx: &WorkerContext<T>,
        id: Vec<u8>,
        de_share: DecryptedShares,
        callback: oneshot::Sender<event::Output>,
        timeout: tokio::time::Duration,
        pending_queries: &mut VecDeque<Query>,
    ) -> Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        pending_queries.push_back(Query {
            id: id.clone(),
            deadline,
            callback,
        });

        let action_needed = worker_ctx.context.set_own_de_share(id.clone(), de_share)?;

        if let ActionNeeded::Report(de_share) = action_needed {
            Self::send_report_response(&worker_ctx.transport, &worker_ctx.topic, id, de_share)
                .await
                .map_err(|e| Error::Transport(e.to_string()))?;
        }

        Ok(())
    }

    fn process_expired_queries(pending_queries: &mut VecDeque<Query>, context: &Context) {
        let now = tokio::time::Instant::now();

        while let Some(query) = pending_queries.front() {
            if now >= query.deadline {
                if let Some(query) = pending_queries.pop_front() {
                    Self::complete_query(query, context);
                }
            } else {
                break;
            }
        }
    }

    fn complete_query(query: Query, context: &Context) {
        match context.output(query.id) {
            Ok(output) => {
                if query.callback.send(output).is_err() {
                    log::error!("Failed to send callback, receiver dropped");
                }
            }
            Err(e) => {
                log::error!("Failed to get output: {}", e);
            }
        }
    }

    pub async fn query(&self, id: Vec<u8>, de_shares: DecryptedShares) -> Result<event::Output> {
        let (tx, rx) = oneshot::channel();

        let cmd_tx = self
            .command_tx
            .as_ref()
            .ok_or_else(|| Error::Query("Collector not started".to_string()))?;

        cmd_tx
            .send(Command::Query {
                id,
                de_shares,
                callback: tx,
            })
            .await
            .map_err(|_| Error::ChannelClosed)?;

        rx.await.map_err(|_| Error::ChannelClosed)
    }

    pub fn stop(&mut self) {
        if let Some(cmd_tx) = self.command_tx.take() {
            let _ = cmd_tx.try_send(Command::Shutdown);
        }

        if let Some(handle) = self.worker_handle.take() {
            handle.abort();
        }
    }
}

impl<T: Transport> Drop for Collector<T> {
    fn drop(&mut self) {
        self.stop();
    }
}
