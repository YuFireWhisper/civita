use std::{
    collections::{HashMap, HashSet, VecDeque},
    marker::PhantomData,
    sync::Arc,
};

use tokio::sync::{mpsc, oneshot};

use crate::{
    crypto::{
        dkg::joint_feldman::{
            collector::context::{Context, EventResult},
            peer_info::PeerRegistry,
        },
        keypair::{self, SecretKey},
        primitives::{
            algebra::element::{self, Point, Scalar},
            vss::{Shares, Vss},
        },
    },
    network::transport::{libp2p_transport::protocols::gossipsub, Transport},
};

pub mod config;
mod context;

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

    #[error("Element error: {0}")]
    Element(#[from] element::Error),

    #[error("Share not found")]
    ShareNotFound,

    #[error("Keypair error: {0}")]
    Keypair(#[from] keypair::Error),
}

pub enum CollectionResult {
    Success {
        own_shares: Vec<Scalar>,
        partial_public: HashMap<libp2p::PeerId, Point>,
    },
    Failure {
        invalid_peers: HashSet<libp2p::PeerId>,
    },
}

enum Command {
    Query {
        id: Vec<u8>,
        raw_share: Vec<u8>,
        callback: oneshot::Sender<EventResult>,
    },
    Shutdown,
}

struct Query {
    id: Vec<u8>,
    deadline: tokio::time::Instant,
    callback: oneshot::Sender<EventResult>,
}

struct WorkerContext<T: Transport> {
    context: Context,
    transport: Arc<T>,
    topic: String,
}

pub struct Collector<T, V>
where
    T: Transport + 'static,
    V: Vss + 'static,
{
    transport: Arc<T>,
    secret_key: SecretKey,
    config: Config,
    command_tx: Option<mpsc::Sender<Command>>,
    worker_handle: Option<tokio::task::JoinHandle<()>>,
    _marker: PhantomData<V>,
}

impl CollectionResult {
    pub fn from_shares(
        shares: HashMap<libp2p::PeerId, Shares>,
        own_index: u16,
        secret_key: &SecretKey,
    ) -> Result<Self> {
        let mut own_shares = Vec::with_capacity(shares.len());
        let mut partial_public = HashMap::with_capacity(shares.len());

        for (peer, share) in shares {
            let encrypted_share = share.shares.get(&own_index).ok_or(Error::ShareNotFound)?;
            let decrypted_share = secret_key.decrypt(encrypted_share)?;

            let share_scalar = Scalar::from_slice(&decrypted_share)?;
            own_shares.push(share_scalar);

            let public_point = Point::from_slice(&share.commitments[0])?;
            partial_public.insert(peer, public_point);
        }

        Ok(CollectionResult::Success {
            own_shares,
            partial_public,
        })
    }
}

impl<T, V> Collector<T, V>
where
    T: Transport + 'static,
    V: Vss + 'static,
{
    pub fn new(transport: Arc<T>, secret_key: SecretKey, config: Config) -> Self {
        Self {
            transport,
            secret_key,
            config,
            command_tx: None,
            worker_handle: None,
            _marker: PhantomData,
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

        let handle = tokio::spawn(Self::run_worker(
            peers,
            secret_key,
            transport,
            topic,
            command_rx,
            gossipsub_rx,
            timeout,
        ));

        self.worker_handle = Some(handle);
        Ok(())
    }

    async fn run_worker(
        peers: PeerRegistry,
        secret_key: SecretKey,
        transport: Arc<T>,
        topic: String,
        mut command_rx: mpsc::Receiver<Command>,
        mut gossipsub_rx: mpsc::Receiver<gossipsub::Message>,
        timeout: tokio::time::Duration,
    ) {
        let context = Context::new(peers, secret_key, transport.self_peer());
        let mut worker_ctx = WorkerContext {
            context,
            transport,
            topic,
        };
        let mut pending_queries = VecDeque::new();
        let mut check_timer = tokio::time::interval(tokio::time::Duration::from_secs(1));

        loop {
            tokio::select! {
                Some(msg) = gossipsub_rx.recv() => {
                    if let Err(e) = Self::process_message(&mut worker_ctx, msg).await {
                        log::error!("Failed to process message: {}", e);
                    }
                }

                Some(cmd) = command_rx.recv() => {
                    match cmd {
                        Command::Query { id, raw_share, callback } => {
                            Self::handle_query(&mut worker_ctx, id, raw_share, callback, timeout, &mut pending_queries).await;
                        }
                        Command::Shutdown => break,
                    }
                }

                _ = check_timer.tick() => {
                    Self::process_expired_queries(&mut pending_queries, &mut worker_ctx.context);
                    Self::respond_to_self_reports(&mut worker_ctx).await;
                }

                else => break,
            }
        }

        log::info!("Collector worker stopped");
    }

    async fn handle_query(
        worker_ctx: &mut WorkerContext<T>,
        id: Vec<u8>,
        raw_share: Vec<u8>,
        callback: oneshot::Sender<EventResult>,
        timeout: tokio::time::Duration,
        pending_queries: &mut VecDeque<Query>,
    ) {
        let deadline = tokio::time::Instant::now() + timeout;
        pending_queries.push_back(Query {
            id: id.clone(),
            deadline,
            callback,
        });

        if let Ok(Some(own_share)) = worker_ctx.context.set_own_share(id.clone(), raw_share) {
            for reporter in worker_ctx.context.get_pending_reports_against_self(&id) {
                Self::send_report_response(
                    &mut worker_ctx.context,
                    &worker_ctx.transport,
                    &worker_ctx.topic,
                    id.clone(),
                    reporter,
                    own_share.clone(),
                )
                .await
                .unwrap_or_else(|e| log::error!("Failed to send report response: {}", e));
            }
        }

        Self::respond_to_self_reports(worker_ctx).await;
    }

    fn process_expired_queries(pending_queries: &mut VecDeque<Query>, context: &mut Context) {
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

    async fn respond_to_self_reports(worker_ctx: &mut WorkerContext<T>) {
        for id in worker_ctx.context.active_event_ids() {
            let id_vec = id.to_vec();

            if let Ok(Some(own_share)) = worker_ctx.context.own_share_clone(&id) {
                for reporter in worker_ctx.context.get_pending_reports_against_self(&id_vec) {
                    if let Err(e) = Self::send_report_response(
                        &mut worker_ctx.context,
                        &worker_ctx.transport,
                        &worker_ctx.topic,
                        id_vec.clone(),
                        reporter,
                        own_share.to_vec(),
                    )
                    .await
                    {
                        log::error!("Failed to send report response: {}", e);
                    }
                }
            }
        }
    }

    async fn process_message(
        worker_ctx: &mut WorkerContext<T>,
        msg: gossipsub::Message,
    ) -> Result<()> {
        match msg.payload {
            gossipsub::Payload::VSSShares { id, shares } => {
                Self::handle_vss_shares(worker_ctx, id, msg.source, shares)?
            }
            gossipsub::Payload::VSSReport { id, reported } => {
                Self::handle_report(worker_ctx, id, msg.source, reported).await?
            }
            gossipsub::Payload::VSSReportResponse { id, raw_share } => {
                Self::handle_report_response(worker_ctx, id, msg.source, raw_share)?
            }
            _ => {}
        }

        Ok(())
    }

    fn handle_vss_shares(
        worker_ctx: &mut WorkerContext<T>,
        id: Vec<u8>,
        source: libp2p::PeerId,
        shares: Shares,
    ) -> Result<()> {
        worker_ctx.context.add_event::<V>(id, source, shares)?;
        Ok(())
    }

    async fn handle_report(
        worker_ctx: &mut WorkerContext<T>,
        id: Vec<u8>,
        reporter: libp2p::PeerId,
        reported: libp2p::PeerId,
    ) -> Result<()> {
        if reported == worker_ctx.transport.self_peer() {
            if let Ok(Some(share)) = worker_ctx.context.own_share_clone(&id) {
                Self::send_report_response(
                    &mut worker_ctx.context,
                    &worker_ctx.transport,
                    &worker_ctx.topic,
                    id.clone(),
                    reporter,
                    share,
                )
                .await?;
            }
        }
        worker_ctx.context.add_report_peer(id, reporter, reported)?;
        Ok(())
    }

    fn handle_report_response(
        worker_ctx: &mut WorkerContext<T>,
        id: Vec<u8>,
        reported: libp2p::PeerId,
        raw_share: Vec<u8>,
    ) -> Result<()> {
        for peer in worker_ctx.context.get_reporters_of(&id, reported) {
            worker_ctx.context.add_report_response::<V>(
                id.clone(),
                peer,
                reported,
                raw_share.clone(),
            )?;
        }
        Ok(())
    }

    async fn send_report_response(
        context: &mut Context,
        transport: &Arc<T>,
        topic: &str,
        id: Vec<u8>,
        reporter: libp2p::PeerId,
        own_share: Vec<u8>,
    ) -> Result<()> {
        let payload = gossipsub::Payload::VSSReportResponse {
            id: id.clone(),
            raw_share: own_share,
        };

        transport
            .publish(topic, payload)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;

        context.mark_self_report_as_responded(&id, &reporter)?;

        Ok(())
    }

    fn complete_query(query: Query, context: &mut Context) {
        match context.output(query.id.clone()) {
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

    pub async fn query(&self, id: Vec<u8>, raw_share: Vec<u8>) -> Result<CollectionResult> {
        let (tx, rx) = oneshot::channel();

        let cmd_tx = self
            .command_tx
            .as_ref()
            .ok_or_else(|| Error::Query("Collector not started".to_string()))?;

        cmd_tx
            .send(Command::Query {
                id,
                raw_share,
                callback: tx,
            })
            .await
            .map_err(|_| Error::ChannelClosed)?;

        let result = rx.await.map_err(|_| Error::ChannelClosed)?;

        match result {
            EventResult::Success { own_index, shares } => {
                CollectionResult::from_shares(shares, own_index, &self.secret_key)
            }
            EventResult::Failure { invalid_peers } => {
                Ok(CollectionResult::Failure { invalid_peers })
            }
        }
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

impl<T: Transport, V: Vss> Drop for Collector<T, V> {
    fn drop(&mut self) {
        self.stop();
    }
}

