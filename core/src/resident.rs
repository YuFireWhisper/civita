use std::{collections::HashMap, sync::Arc};

use libp2p::PeerId;

use crate::{
    consensus::{
        engine,
        graph::{self, CreationError, StorageMode},
        validator::Validator,
        Engine,
    },
    crypto::Multihash,
    network::Transport,
    ty::{
        atom::{Command, Height},
        token::Token,
    },
};

const GOSSIP_TOPIC: u8 = 0;
const REQUEST_RESPONSE_TOPIC: u8 = 1;
const BOOTSTRAP_TOPIC: u8 = 2;

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Engine(#[from] engine::Error),
}

pub struct Config {
    bootstrap_peers: Vec<PeerId>,
    bootstrap_timeout: tokio::time::Duration,
    heartbeat_interval: Option<tokio::time::Duration>,

    block_threshold: u32,
    checkpoint_distance: Height,
    target_block_time: u64,
    init_vdf_difficulty: u64,
    max_difficulty_adjustment: f32,
    storage_mode: StorageMode,
    vdf_params: u16,
}

pub struct Resident<V> {
    transport: Arc<Transport>,
    engine: Arc<Engine<V>>,
}

impl<V: Validator> Resident<V> {
    pub async fn new(transport: Arc<Transport>, config: Config) -> Result<Self> {
        let graph_config = graph::Config {
            block_threshold: config.block_threshold,
            checkpoint_distance: config.checkpoint_distance,
            target_block_time: config.target_block_time,
            init_vdf_difficulty: config.init_vdf_difficulty,
            max_difficulty_adjustment: config.max_difficulty_adjustment,
            storage_mode: config.storage_mode,
            vdf_params: config.vdf_params,
        };

        let engine_config = engine::Config {
            gossip_topic: GOSSIP_TOPIC,
            request_response_topic: REQUEST_RESPONSE_TOPIC,
            bootstrap_topic: BOOTSTRAP_TOPIC,
            graph_config,
            bootstrap_peers: config.bootstrap_peers,
            bootstrap_timeout: config.bootstrap_timeout,
            heartbeat_interval: config.heartbeat_interval,
        };

        let engine = Engine::new(transport.clone(), engine_config).await?;

        Ok(Self { transport, engine })
    }

    pub async fn propose(
        &self,
        cmd: Command,
        sigs: HashMap<Multihash, Vec<u8>>,
    ) -> Result<(), CreationError> {
        self.engine.propose(cmd, sigs).await
    }

    pub async fn tokens(&self) -> HashMap<Multihash, Token> {
        self.engine.tokens().await
    }
}
