use std::sync::Arc;

use derivative::Derivative;
use libp2p::{Multiaddr, PeerId};

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

#[derive(Clone, Copy)]
#[derive(Derivative)]
#[derivative(Default)]
pub struct Config {
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

    #[derivative(Default(value = "Some(tokio::time::Duration::from_mins(5))"))]
    pub heartbeat_interval: Option<tokio::time::Duration>,
}

pub struct Resident<V> {
    transport: Arc<Transport>,
    engine: Arc<Engine<V>>,
}

impl<V: Validator> Resident<V> {
    pub async fn new(
        transport: Arc<Transport>,
        peers: Vec<(PeerId, Multiaddr)>,
        timeout: tokio::time::Duration,
        dir: &str,
        config: Config,
    ) -> Result<Self> {
        let config = engine::Config {
            gossip_topic: GOSSIP_TOPIC,
            block_threshold: config.block_threshold,
            checkpoint_distance: config.checkpoint_distance,
            target_block_time: config.target_block_time,
            init_vdf_difficulty: config.init_vdf_difficulty,
            max_difficulty_adjustment: config.max_difficulty_adjustment,
            vdf_params: config.vdf_params,
            heartbeat_interval: config.heartbeat_interval,
        };

        let engine = Engine::new(transport.clone(), peers, timeout, dir, config).await?;
        Ok(Resident { transport, engine })
    }

    pub async fn genesis(transport: Arc<Transport>, dir: &str, config: Config) -> Result<Self> {
        let config = engine::Config {
            gossip_topic: GOSSIP_TOPIC,
            block_threshold: config.block_threshold,
            checkpoint_distance: config.checkpoint_distance,
            target_block_time: config.target_block_time,
            init_vdf_difficulty: config.init_vdf_difficulty,
            max_difficulty_adjustment: config.max_difficulty_adjustment,
            vdf_params: config.vdf_params,
            heartbeat_interval: config.heartbeat_interval,
        };

        let engine = Engine::with_genesis(transport.clone(), dir, config).await?;
        Ok(Resident { transport, engine })
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

    pub fn listen_addr(&self) -> Multiaddr {
        self.transport.listen_addr()
    }

    pub async fn status(&self) -> Status {
        self.engine.status().await
    }
}
