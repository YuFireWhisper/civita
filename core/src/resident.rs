use std::sync::Arc;

use derivative::Derivative;
use libp2p::{identity::Keypair, Multiaddr, PeerId};

use crate::{
    consensus::{
        engine,
        graph::{self, Status},
        validator::Validator,
        Engine,
    },
    crypto::Multihash,
    network::{transport, Transport},
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
}

#[derive(Clone)]
#[derive(Derivative)]
#[derivative(Default)]
pub struct Config {
    // Graph config
    #[derivative(Default(value = "1000"))]
    pub block_threshold: u32,

    #[derivative(Default(value = "6"))]
    pub checkpoint_distance: u32,

    #[derivative(Default(value = "60"))]
    pub target_block_time: u64,

    #[derivative(Default(value = "50000"))]
    pub init_vdf_difficulty: u64,

    #[derivative(Default(value = "0.1"))]
    pub max_difficulty_adjustment: f32,

    #[derivative(Default(value = "1024"))]
    pub vdf_params: u16,

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
}

pub struct Resident<V> {
    engine: Arc<Engine<V>>,
    listen_addr: Multiaddr,
}

impl<V: Validator> Resident<V> {
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

        let engine_config = engine::Config {
            gossip_topic: GOSSIP_TOPIC,
            block_threshold: config.block_threshold,
            checkpoint_distance: config.checkpoint_distance,
            target_block_time: config.target_block_time,
            init_vdf_difficulty: config.init_vdf_difficulty,
            max_difficulty_adjustment: config.max_difficulty_adjustment,
            vdf_params: config.vdf_params,
            heartbeat_interval: config.heartbeat_interval,
        };

        let bc = if config.bootstrap_peers.is_empty() {
            None
        } else {
            Some(BootstrapConfig {
                peers: config.bootstrap_peers.clone(),
                timeout: config.bootstrap_timeout,
            })
        };

        let engine = Engine::new(transport, &config.storage_dir, bc, engine_config).await?;

        Ok(Self {
            engine,
            listen_addr,
        })
    }

    pub async fn propose(
        &self,
        code: u8,
        inputs: impl IntoIterator<Item = (Multihash, impl Into<Vec<u8>>)>,
        created: impl IntoIterator<Item = (impl Into<Vec<u8>>, impl Into<Vec<u8>>)>,
    ) -> Result<(), Error> {
        self.engine
            .propose(code, inputs, created)
            .await
            .map_err(Error::from)
    }

    pub async fn tokens(&self) -> Vec<Token> {
        self.engine.tokens().await
    }

    pub fn listen_addr(&self) -> &Multiaddr {
        &self.listen_addr
    }

    pub async fn status(&self) -> Status {
        self.engine.status().await
    }
}
