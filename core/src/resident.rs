use std::{collections::HashMap, sync::Arc};

use derivative::Derivative;
use libp2p::{identity::Keypair, Multiaddr, PeerId};

use crate::{
    consensus::{
        engine::{self, EngineConfig, NodeType},
        graph::{self, Status},
        Engine,
    },
    crypto::Multihash,
    network::{transport, Transport},
    traits,
    ty::token::Token,
};

pub use engine::BootstrapConfig;

const GOSSIP_TOPIC: u8 = 0;

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Engine(#[from] engine::Error),

    #[error(transparent)]
    Graph(#[from] graph::Error),

    #[error(transparent)]
    Transport(#[from] transport::Error),

    #[error("{0}")]
    Propose(String),

    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),
}

#[derive(Clone)]
#[derive(Derivative)]
#[derivative(Default)]
pub struct Config {
    // Engine config
    #[derivative(Default(value = "Some(tokio::time::Duration::from_mins(5))"))]
    pub heartbeat_interval: Option<tokio::time::Duration>,

    // Transport config
    #[derivative(Default(value = "tokio::time::Duration::from_millis(100)"))]
    pub check_listen_timeout: tokio::time::Duration,

    #[derivative(Default(value = "1000"))]
    pub channel_size: usize,

    #[derivative(Default(value = "tokio::time::Duration::from_secs(5)"))]
    pub get_swarm_lock_timeout: tokio::time::Duration,

    #[derivative(Default(value = "tokio::time::Duration::from_secs(10)"))]
    pub wait_for_gossipsub_peer_timeout: tokio::time::Duration,

    #[derivative(Default(value = "tokio::time::Duration::from_millis(100)"))]
    pub wait_for_gossipsub_peer_interval: tokio::time::Duration,

    #[derivative(Default(value = "tokio::time::Duration::from_millis(100)"))]
    pub wait_next_event_timeout: tokio::time::Duration,

    #[derivative(Default(value = "tokio::time::Duration::from_millis(100)"))]
    pub receive_interval: tokio::time::Duration,

    #[derivative(Default(value = "\"/ip4/0.0.0.0/tcp/0\".parse().unwrap()"))]
    pub listen_addr: Multiaddr,

    #[derivative(Default(value = "\"./data\".to_string()"))]
    pub storage_dir: String,

    pub bootstrap_peers: Vec<(PeerId, Multiaddr)>,

    #[derivative(Default(value = "tokio::time::Duration::from_secs(5)"))]
    pub bootstrap_timeout: tokio::time::Duration,

    #[derivative(Default(value = "NodeType::Archive"))]
    pub node_type: NodeType,
}

pub struct Resident<T: traits::Config> {
    handle: engine::Handle<T>,
    listen_addr: Multiaddr,
}

impl<T: traits::Config> Resident<T> {
    pub async fn new(keypair: Keypair, config: Config) -> Result<Self> {
        let transport_config = transport::Config {
            check_listen_timeout: config.check_listen_timeout,
            channel_capacity: config.channel_size,
            get_swarm_lock_timeout: config.get_swarm_lock_timeout,
            wait_for_gossipsub_peer_timeout: config.wait_for_gossipsub_peer_timeout,
            wait_for_gossipsub_peer_interval: config.wait_for_gossipsub_peer_interval,
            wait_next_event_timeout: config.wait_next_event_timeout,
            receive_interval: config.receive_interval,
        };

        let tranpsort = Transport::new(keypair, config.listen_addr, transport_config).await?;
        let transport = Arc::new(tranpsort);
        let listen_addr = transport.listen_addr();

        let engine_config = EngineConfig {
            gossip_topic: GOSSIP_TOPIC,
            heartbeat_interval: config.heartbeat_interval,
        };

        let bc = if config.bootstrap_peers.is_empty() {
            None
        } else {
            Some(BootstrapConfig {
                peers: config.bootstrap_peers.clone(),
                timeout: config.bootstrap_timeout,
                node_type: config.node_type,
            })
        };

        Ok(Self {
            handle: Engine::spawn(transport, &config.storage_dir, bc, engine_config).await?,
            listen_addr,
        })
    }

    pub async fn propose(
        &self,
        code: u8,
        on_chain_inputs: Vec<(Multihash, T::ScriptSig)>,
        off_chain_inputs: Vec<T::OffChainInput>,
        outpus: Vec<Token<T>>,
    ) -> Result<(), Error> {
        self.handle
            .propose(code, on_chain_inputs, off_chain_inputs, outpus)
            .await
            .await?
            .map_err(|e| Error::Propose(e.to_string()))
    }

    pub async fn tokens(&self) -> Result<HashMap<Multihash, Token<T>>> {
        self.handle.tokens().await.await.map_err(Error::from)
    }

    pub fn listen_addr(&self) -> &Multiaddr {
        &self.listen_addr
    }

    pub async fn status(&self) -> Result<Status> {
        self.handle.status().await.await.map_err(Error::from)
    }
}
