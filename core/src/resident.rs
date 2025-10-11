use std::collections::HashMap;

use derivative::Derivative;
use libp2p::{identity::Keypair, Multiaddr, PeerId};

use crate::{
    consensus::{
        engine::{self, Engine, NodeType},
        tree::Status,
    },
    crypto::Multihash,
    network::{transport, Transport},
    traits,
    ty::token::Token,
};

pub use engine::BootstrapConfig;

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),
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

pub struct Resident<T: traits::Config> {
    handle: engine::Handle<T>,
    listen_addr: Multiaddr,
}

impl<T: traits::Config> Resident<T> {
    pub async fn new(keypair: Keypair, config: Config) -> Result<Self> {
        let transport_config = transport::Config {
            listen_timeout: config.listen_timeout,
            channel_capacity: config.channel_size,
            dial_timeout: config.dial_timeout,
        };

        let transport = Transport::new(
            keypair,
            config.listen_addr,
            config
                .bootstrap_peer
                .clone()
                .map(|(peer_id, addr)| vec![(peer_id, addr)])
                .unwrap_or_default(),
            transport_config,
        )
        .await;

        let listen_addr = transport.addr.clone();

        let bc = config.bootstrap_peer.map(|(peer, _)| BootstrapConfig {
            peer,
            timeout: config.bootstrap_timeout,
            node_type: config.node_type,
        });

        Ok(Self {
            handle: Engine::spawn(
                transport,
                &config.storage_dir,
                config.heartbeat_interval,
                bc,
            )
            .await,
            listen_addr,
        })
    }

    pub async fn propose(
        &self,
        code: u8,
        on_chain_inputs: Vec<(Multihash, T::ScriptSig)>,
        off_chain_inputs: Vec<T::OffChainInput>,
        outpus: Vec<Token<T>>,
    ) {
        self.handle
            .propose(code, on_chain_inputs, off_chain_inputs, outpus)
            .await
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

    pub async fn stop(self) {
        self.handle.stop().await
    }

    pub fn handle(&self) -> engine::Handle<T> {
        self.handle.clone()
    }
}
