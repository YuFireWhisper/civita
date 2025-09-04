use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

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
        atom::{Atom, Command, Height},
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
    pub heartbeat_interval: Option<tokio::time::Duration>,

    pub block_threshold: u32,
    pub checkpoint_distance: Height,
    pub target_block_time: u64,
    pub init_vdf_difficulty: u64,
    pub max_difficulty_adjustment: f32,
    pub storage_mode: StorageMode,
    pub vdf_params: u16,
}

pub struct Resident<V> {
    transport: Arc<Transport>,
    engine: Arc<Engine<V>>,
}

impl<V: Validator> Resident<V> {
    pub async fn new(
        transport: Arc<Transport>,
        peers: Vec<PeerId>,
        timeout: tokio::time::Duration,
        config: Config,
    ) -> Result<Self> {
        let graph_config = graph::Config {
            block_threshold: config.block_threshold,
            checkpoint_distance: config.checkpoint_distance,
            target_block_time: config.target_block_time,
            init_vdf_difficulty: config.init_vdf_difficulty,
            max_difficulty_adjustment: config.max_difficulty_adjustment,
            storage_mode: config.storage_mode,
            vdf_params: config.vdf_params,
        };

        let bootstrap_config = engine::BootstrapConfig {
            peers,
            timeout,
            topic: BOOTSTRAP_TOPIC,
        };

        let engine_config = engine::Config {
            gossip_topic: GOSSIP_TOPIC,
            request_response_topic: REQUEST_RESPONSE_TOPIC,
            heartbeat_interval: config.heartbeat_interval,
        };

        let engine = Engine::new(
            transport.clone(),
            graph_config,
            bootstrap_config,
            engine_config,
        )
        .await?;

        Ok(Self { transport, engine })
    }

    pub async fn with_genesis(
        transport: Arc<Transport>,
        atom: Atom,
        trie_root: Multihash,
        trie_guide: HashMap<Multihash, Vec<u8>>,
        related_keys: HashSet<Multihash>,
        config: Config,
    ) -> Result<Self> {
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
            heartbeat_interval: config.heartbeat_interval,
        };

        let engine = Engine::with_genesis(
            transport.clone(),
            atom,
            trie_root,
            trie_guide,
            related_keys,
            graph_config,
            engine_config,
        )
        .await?;

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
