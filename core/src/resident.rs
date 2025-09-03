use std::{collections::HashMap, sync::Arc};

use libp2p::PeerId;

use crate::{
    consensus::{
        engine,
        graph::{self, CreationError},
        validator::Validator,
        Engine,
    },
    crypto::Multihash,
    network::Transport,
    ty::atom::Command,
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
    graph_config: graph::Config,
    bootstrap_peers: Vec<PeerId>,
    bootstrap_timeout: tokio::time::Duration,
}

pub struct Resident<V> {
    transport: Arc<Transport>,
    engine: Arc<Engine<V>>,
}

impl<V: Validator> Resident<V> {
    pub async fn new(transport: Arc<Transport>, config: Config) -> Result<Self> {
        let config = engine::Config {
            gossip_topic: GOSSIP_TOPIC,
            request_response_topic: REQUEST_RESPONSE_TOPIC,
            bootstrap_topic: BOOTSTRAP_TOPIC,
            graph_config: config.graph_config,
            bootstrap_peers: config.bootstrap_peers,
            bootstrap_timeout: config.bootstrap_timeout,
        };

        let engine = Engine::new(transport.clone(), config).await?;

        Ok(Self { transport, engine })
    }

    pub async fn propose(
        &self,
        cmd: Command,
        sigs: HashMap<Multihash, Vec<u8>>,
    ) -> Result<(), CreationError> {
        self.engine.propose(cmd, sigs).await
    }
}
