use std::sync::Arc;

use libp2p::{identity::Keypair, Multiaddr, PeerId};
use multihash_derive::MultihashDigest;

use crate::{
    consensus::{
        engine,
        graph::{self, StorageMode},
        validator::Validator,
        Engine,
    },
    crypto::{Hasher, Multihash},
    network::{transport, Transport},
    ty::{
        atom::{Atom, Command, Height},
        token::Token,
    },
    utils::mmr::Mmr,
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

#[derive(Default)]
pub struct Builder {
    tx_info: Option<(Keypair, libp2p::Multiaddr, transport::Config)>,
    genesis_info: Option<(u8, Vec<Token>, Mmr<Token>)>,
    normal: Option<(Vec<(PeerId, Multiaddr)>, tokio::time::Duration)>,
    config: Option<Config>,
}

pub struct Resident<V> {
    engine: Arc<Engine<V>>,
}

impl Builder {
    pub fn with_transport_info(
        mut self,
        keypair: Keypair,
        listen_addr: libp2p::Multiaddr,
        config: transport::Config,
    ) -> Self {
        self.tx_info = Some((keypair, listen_addr, config));
        self
    }

    pub fn with_genesis_info<I, T, U>(mut self, code: u8, tokens: I) -> Self
    where
        I: IntoIterator<Item = (T, U)>,
        T: Into<Vec<u8>>,
        U: Into<Vec<u8>>,
    {
        assert!(self.normal.is_none(), "Normal info is already set");
        assert!(self.genesis_info.is_none(), "Genesis info is already set");

        let (mut mmr, tokens) = tokens.into_iter().enumerate().fold(
            (Mmr::default(), vec![]),
            |(mut mmr, mut tokens), (idx, (value, sig))| {
                let token = Token::new(&Multihash::default(), idx as u32, value.into(), sig);
                mmr.append(token.id, token.clone());
                tokens.push(token);
                (mmr, tokens)
            },
        );
        mmr.commit();

        self.genesis_info = Some((code, tokens, mmr));
        self
    }

    pub fn with_normal_info(
        mut self,
        peers: Vec<(PeerId, Multiaddr)>,
        timeout: tokio::time::Duration,
    ) -> Self {
        assert!(self.genesis_info.is_none(), "Genesis info is already set");
        assert!(self.normal.is_none(), "Normal info is already set");

        self.normal = Some((peers, timeout));
        self
    }

    pub fn with_config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }

    pub async fn build<V: Validator>(self) -> Result<Resident<V>> {
        let (keypair, listen_addr, config) = self.tx_info.expect("Transport info is required");
        let tx = Arc::new(Transport::new(keypair, listen_addr, config).await?);

        let config = self.config.expect("Config is required");
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
            heartbeat_interval: config.heartbeat_interval,
        };

        if let Some((code, tokens, mmr)) = self.genesis_info {
            let cmd = Command {
                code,
                inputs: vec![],
                created: tokens,
            };

            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let mut atom = Atom {
                hash: Multihash::default(),
                parent: Multihash::default(),
                checkpoint: Multihash::default(),
                height: 0,
                nonce: vec![],
                timestamp,
                cmd: Some(cmd),
                atoms: vec![],
            };

            atom.hash = Hasher::default().digest(&atom.hash_input());

            let engine = Engine::with_genesis(tx, atom, mmr, graph_config, engine_config).await?;
            return Ok(Resident { engine });
        }

        if let Some((peers, timeout)) = self.normal {
            let engine = Engine::new(tx, peers, timeout, graph_config, engine_config).await?;
            return Ok(Resident { engine });
        }

        panic!("Either genesis info or normal info must be set");
    }
}

impl<V: Validator> Resident<V> {
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
}
