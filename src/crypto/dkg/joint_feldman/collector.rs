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
        keypair::SecretKey,
        primitives::{
            algebra::element::{Public, Secret},
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
}

pub enum CollectionResult<SK, PK> {
    Success {
        own_shares: Vec<SK>,
        partial_public: HashMap<libp2p::PeerId, PK>,
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

pub struct Collector<T, SK, PK, V>
where
    T: Transport + 'static,
    SK: Secret + 'static,
    PK: Public + 'static,
    V: Vss<SK, PK> + 'static,
{
    transport: Arc<T>,
    secret_key: SecretKey,
    config: Config,
    command_tx: Option<mpsc::Sender<Command>>,
    worker_handle: Option<tokio::task::JoinHandle<()>>,
    _marker: PhantomData<(SK, PK, V)>,
}

impl<SK, PK> CollectionResult<SK, PK>
where
    SK: Secret,
    PK: Public,
{
    pub fn from_shares(
        shares: HashMap<libp2p::PeerId, Shares>,
        own_index: u16,
        secret_key: &SecretKey,
    ) -> Self {
        let (own_shares, partial_public): (Vec<_>, HashMap<_, _>) = shares
            .into_iter()
            .map(|(peer, share)| {
                let encrypted_share = share.shares.get(&own_index).expect("Own share not found");
                let decrypted_share = secret_key
                    .decrypt(encrypted_share)
                    .expect("Decryption failed");
                let partial_public = share.commitments[0].to_owned();

                (
                    SK::from_bytes(&decrypted_share),
                    (peer, PK::from_bytes(&partial_public)),
                )
            })
            .collect();

        CollectionResult::Success {
            own_shares,
            partial_public,
        }
    }
}

impl<T, SK, PK, V> Collector<T, SK, PK, V>
where
    T: Transport + 'static,
    SK: Secret + 'static,
    PK: Public + 'static,
    V: Vss<SK, PK> + 'static,
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

        let handle = tokio::spawn(Self::run_worker(
            peers,
            secret_key,
            transport,
            topic,
            command_rx,
            gossipsub_rx,
            self.config.timeout,
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
        let mut ctx = Context::new(peers, secret_key, transport.self_peer());
        let mut pending_queries: VecDeque<Query> = VecDeque::new();

        let mut check_timer = tokio::time::interval(tokio::time::Duration::from_secs(1));

        loop {
            tokio::select! {
                Some(msg) = gossipsub_rx.recv() => {
                    if let Err(e) = Self::process_message(&mut ctx, &transport, &topic, msg).await {
                        log::error!("Failed to process message: {}", e);
                    }
                }

                Some(cmd) = command_rx.recv() => {
                    match cmd {
                        Command::Query { id, raw_share, callback } => {
                            let deadline = tokio::time::Instant::now() + timeout;
                            pending_queries.push_back(Query { id: id.clone(), deadline, callback });

                            let result = ctx.set_own_share(id.clone(), raw_share).unwrap_or(None);
                            if let Some(own_share) = result {
                                for reporter in ctx.get_pending_reports_against_self(&id) {
                                    Self::send_report_response(&mut ctx, &transport, &topic, id.clone(), reporter, own_share.clone()).await
                                        .unwrap_or_else(|e| log::error!("Failed to send report response: {}", e));
                                }
                            }

                            Self::check_self_reports(&mut ctx, &transport, &topic).await;
                        }
                        Command::Shutdown => break,
                    }
                }

                _ = check_timer.tick() => {
                    Self::check_queries(&mut pending_queries, &mut ctx);
                    Self::check_self_reports(&mut ctx, &transport, &topic).await;
                }

                else => break,
            }
        }

        log::info!("Collector worker stopped");
    }

    fn check_queries(pending_queries: &mut VecDeque<Query>, ctx: &mut Context) {
        let now = tokio::time::Instant::now();

        while let Some(query) = pending_queries.front() {
            if now >= query.deadline {
                if let Some(query) = pending_queries.pop_front() {
                    Self::process_query(query, ctx);
                }
            } else {
                break;
            }
        }
    }

    async fn check_self_reports(ctx: &mut Context, transport: &Arc<T>, topic: &str) {
        for id in ctx.active_event_ids() {
            let id_vec = id.to_vec();

            if let Ok(Some(own_share)) = ctx.own_share_clone(&id) {
                for reporter in ctx.get_pending_reports_against_self(&id_vec) {
                    if let Err(e) = Self::send_report_response(
                        ctx,
                        transport,
                        topic,
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
        ctx: &mut Context,
        transport: &Arc<T>,
        topic: &str,
        msg: gossipsub::Message,
    ) -> Result<()> {
        match msg.payload {
            gossipsub::Payload::VSSShares { id, shares } => {
                ctx.add_event::<SK, PK, V>(id, msg.source, shares)?;
            }
            gossipsub::Payload::VSSReport { id, reported } => {
                if reported == transport.self_peer() {
                    if let Ok(Some(share)) = ctx.own_share_clone(&id) {
                        Self::send_report_response(
                            ctx,
                            transport,
                            topic,
                            id.clone(),
                            msg.source,
                            share,
                        )
                        .await?;
                    }
                }
                ctx.add_report_peer(id, msg.source, reported)?;
            }
            gossipsub::Payload::VSSReportResponse { id, raw_share } => {
                let reported = msg.source;

                for peer in ctx.get_reporters_of(&id, reported) {
                    ctx.add_report_response::<SK, PK, V>(
                        id.clone(),
                        peer,
                        reported,
                        raw_share.clone(),
                    )?;
                }
            }
            _ => {}
        }

        Ok(())
    }

    async fn send_report_response(
        ctx: &mut Context,
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

        ctx.mark_self_report_as_responded(&id, &reporter)?;

        Ok(())
    }

    fn process_query(query: Query, ctx: &mut Context) {
        let result = match ctx.output(query.id.clone()) {
            Ok(output) => output,
            Err(e) => {
                log::error!("Failed to get output: {}", e);
                return;
            }
        };

        if query.callback.send(result).is_err() {
            log::error!("Failed to send callback, receiver dropped");
        }
    }

    pub async fn query(&self, id: Vec<u8>, raw_share: Vec<u8>) -> Result<CollectionResult<SK, PK>> {
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
            EventResult::Success { own_index, shares } => Ok(CollectionResult::from_shares(
                shares,
                own_index,
                &self.secret_key,
            )),
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

impl<T, SK, PK, V> Drop for Collector<T, SK, PK, V>
where
    T: Transport,
    SK: Secret,
    PK: Public,
    V: Vss<SK, PK>,
{
    fn drop(&mut self) {
        self.stop();
    }
}
