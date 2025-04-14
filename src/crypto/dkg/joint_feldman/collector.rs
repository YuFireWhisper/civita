use std::{
    collections::{HashMap, VecDeque},
    marker::PhantomData,
    sync::Arc,
};

use tokio::sync::{mpsc, oneshot};

use crate::{
    crypto::{
        dkg::joint_feldman::{
            collector::context::{Context, EventOutput},
            peer_info::PeerInfo,
        },
        keypair::SecretKey,
        primitives::{
            algebra::element::{Public, Secret},
            vss::Vss,
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
    Context(String),

    #[error("Channel closed")]
    ChannelClosed,
}

enum Command {
    Query {
        id: Vec<u8>,
        callback: oneshot::Sender<EventOutput>,
    },
    ProcessMessage(gossipsub::Message),
    Shutdown,
}

struct Query {
    id: Vec<u8>,
    interval: tokio::time::Interval,
    callback: oneshot::Sender<EventOutput>,
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

    pub async fn start(&mut self, peers: HashMap<libp2p::PeerId, PeerInfo>) -> Result<()> {
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
        ));

        self.worker_handle = Some(handle);
        Ok(())
    }

    async fn run_worker(
        peers: HashMap<libp2p::PeerId, PeerInfo>,
        secret_key: SecretKey,
        transport: Arc<T>,
        topic: String,
        mut command_rx: mpsc::Receiver<Command>,
        mut gossipsub_rx: mpsc::Receiver<gossipsub::Message>,
    ) {
        let mut ctx = Context::new(peers, secret_key, transport.self_peer());
        let mut pending_queries: VecDeque<Query> = VecDeque::new();

        loop {
            tokio::select! {
                Some(msg) = gossipsub_rx.recv() => {
                    if let Err(e) = Self::process_message(&mut ctx, &transport, &topic, msg).await {
                        log::error!("Failed to process message: {}", e);
                    }
                }

                Some(cmd) = command_rx.recv() => {
                    match cmd {
                        Command::Query { id, callback } => {
                            let interval = tokio::time::interval(std::time::Duration::from_secs(1));
                            pending_queries.push_back(Query { id, interval, callback });
                        }
                        Command::ProcessMessage(msg) => {
                            if let Err(e) = Self::process_message(&mut ctx, &transport, &topic, msg).await {
                                log::error!("Failed to process message: {}", e);
                            }
                        }
                        Command::Shutdown => break,
                    }
                }

                _ = async {
                    if let Some(query) = pending_queries.front_mut() {
                        query.interval.tick().await;
                        Some(query)
                    } else {
                        std::future::pending::<()>().await;
                        None
                    }
                } => {
                    if let Some(query) = pending_queries.pop_front() {
                        Self::process_query(query, &mut ctx);
                    }
                }

                else => break,
            }
        }

        log::info!("Collector worker stopped");
    }

    async fn process_message(
        ctx: &mut Context,
        transport: &Arc<T>,
        topic: &str,
        msg: gossipsub::Message,
    ) -> Result<()> {
        match msg.payload {
            gossipsub::Payload::VSSShares { id, shares } => {
                ctx.add_event::<SK, PK, V>(id, msg.source, shares);
            }
            gossipsub::Payload::VSSReport { id, reported } => {
                if reported == transport.self_peer() {
                    Self::handle_report_to_self(ctx, transport, id, msg.source, topic).await?;
                } else {
                    ctx.add_report_peer(id, reported, msg.source);
                }
            }
            gossipsub::Payload::VSSReportResponse {
                id,
                reporter,
                raw_share,
            } => {
                ctx.add_report_response::<SK, PK, V>(id, reporter, msg.source, raw_share);
            }
            _ => {}
        }

        Ok(())
    }

    async fn handle_report_to_self(
        ctx: &mut Context,
        transport: &Arc<T>,
        id: Vec<u8>,
        reporter: libp2p::PeerId,
        topic: &str,
    ) -> Result<()> {
        let own_share = match ctx.own_share_clone(&id) {
            Ok(Some(share)) => share,
            Ok(None) => return Ok(()), // No share yet, ignore
            Err(e) => return Err(Error::Context(e.to_string())),
        };

        let payload = gossipsub::Payload::VSSReportResponse {
            id,
            reporter,
            raw_share: own_share,
        };

        transport
            .publish(topic, payload)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;

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

        if let Err(_) = query.callback.send(result) {
            log::error!("Failed to send callback, receiver dropped");
        }
    }

    pub async fn query(&self, id: Vec<u8>) -> Result<EventOutput> {
        let (tx, rx) = oneshot::channel();

        let cmd_tx = self
            .command_tx
            .as_ref()
            .ok_or_else(|| Error::Query("Collector not started".to_string()))?;

        cmd_tx
            .send(Command::Query { id, callback: tx })
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

