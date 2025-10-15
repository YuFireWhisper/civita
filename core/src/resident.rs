use std::collections::HashMap;

use derivative::Derivative;
use libp2p::{identity::Keypair, Multiaddr, PeerId};
use tokio::sync::{mpsc, oneshot};

use crate::{
    consensus::{
        engine::{self, Engine, NodeType},
        tree::Status,
    },
    crypto::Multihash,
    event::{Event, Proposal},
    network::{transport, Transport},
    ty::{token::Token, Atom},
    validator::ValidatorEngine,
};

pub use engine::BootstrapConfig;

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),

    #[error("channel closed")]
    ChannelClosed,
}

#[derive(Clone)]
#[derive(Derivative)]
#[derivative(Default)]
pub struct Config {
    // Engine config
    #[derivative(Default(value = "Some(tokio::time::Duration::from_secs(5 * 60))"))]
    pub heartbeat_interval: Option<tokio::time::Duration>,

    // Transport config
    #[derivative(Default(value = "tokio::time::Duration::from_millis(100)"))]
    pub listen_timeout: tokio::time::Duration,

    #[derivative(Default(value = "tokio::time::Duration::from_secs(10)"))]
    pub dial_timeout: tokio::time::Duration,

    #[derivative(Default(value = "1000"))]
    pub channel_size: usize,

    #[derivative(Default(value = "\"/ip4/0.0.0.0/tcp/0\".parse().unwrap()"))]
    pub listen_addr: Multiaddr,

    #[derivative(Default(value = "\"./data\".to_string()"))]
    pub storage_dir: String,

    pub bootstrap_peer: Option<(PeerId, Multiaddr)>,

    #[derivative(Default(value = "tokio::time::Duration::from_secs(15)"))]
    pub bootstrap_timeout: tokio::time::Duration,

    #[derivative(Default(value = "NodeType::Archive"))]
    pub node_type: NodeType,
}

pub struct Resident {
    listen_addr: Multiaddr,
    tx: mpsc::Sender<Event>,
}

impl Resident {
    pub async fn new<V: ValidatorEngine>(keypair: Keypair, config: Config) -> Result<Self> {
        let (tx, rx) = mpsc::channel(config.channel_size);

        let transport_config = transport::Config {
            listen_timeout: config.listen_timeout,
            channel_capacity: config.channel_size,
            dial_timeout: config.dial_timeout,
        };

        let bootstrap_peer = config
            .bootstrap_peer
            .clone()
            .map(|(peer_id, addr)| vec![(peer_id, addr)])
            .unwrap_or_default();

        let transport = Transport::new(
            keypair,
            config.listen_addr,
            bootstrap_peer,
            tx.clone(),
            transport_config,
        )
        .await;

        let listen_addr = transport.addr.clone();

        let bc = BootstrapConfig {
            peer: config.bootstrap_peer.expect("Bootstrap peer is required").0,
            timeout: config.bootstrap_timeout,
            node_type: config.node_type,
        };

        Engine::<V>::spawn(
            transport,
            &config.storage_dir,
            config.heartbeat_interval,
            bc,
            tx.clone(),
            rx,
        )
        .await;

        Ok(Self { tx, listen_addr })
    }

    pub async fn new_genesis<V: ValidatorEngine>(
        atom: Atom,
        keypair: Keypair,
        config: Config,
    ) -> Result<Self> {
        let (tx, rx) = mpsc::channel(config.channel_size);

        let transport_config = transport::Config {
            listen_timeout: config.listen_timeout,
            channel_capacity: config.channel_size,
            dial_timeout: config.dial_timeout,
        };

        let transport = Transport::new(
            keypair,
            config.listen_addr,
            vec![],
            tx.clone(),
            transport_config,
        )
        .await;

        let listen_addr = transport.addr.clone();

        Engine::<V>::spawn_genesis(
            transport,
            &config.storage_dir,
            config.heartbeat_interval,
            tx.clone(),
            rx,
            atom,
        )
        .await;

        Ok(Self { tx, listen_addr })
    }

    pub async fn propose(&self, proposal: Proposal) {
        let event = Event::Propose(proposal);
        let _ = self.tx.send(event).await;
    }

    pub async fn tokens(&self) -> Result<HashMap<Multihash, Token>> {
        let (tx, rx) = oneshot::channel();
        let event = Event::Tokens(tx);
        let _ = self.tx.send(event).await;
        rx.await.map_err(|_| Error::ChannelClosed)
    }

    pub fn listen_addr(&self) -> &Multiaddr {
        &self.listen_addr
    }

    pub async fn status(&self) -> Result<Status> {
        let (tx, rx) = oneshot::channel();
        let event = Event::Status(tx);
        let _ = self.tx.send(event).await;
        rx.await.map_err(|_| Error::ChannelClosed)
    }

    pub async fn stop(self) {
        let (tx, rx) = oneshot::channel();
        let event = Event::Stop(tx);
        let _ = self.tx.send(event).await;
        let _ = rx.await;
    }
}
