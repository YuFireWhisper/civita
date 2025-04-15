use std::{collections::HashMap, sync::Arc};

use crate::{
    crypto::{
        dkg::{
            joint_feldman::{
                collector::{CollectionResult, Collector},
                distributor::Distributor,
                peer_info::PeerRegistry,
            },
            Dkg_, GenerateResult,
        },
        keypair::{PublicKey, SecretKey},
        primitives::{
            algebra::element::Scalar,
            vss::{Shares, Vss},
        },
    },
    network::transport::Transport,
};

mod collector;
mod config;
mod distributor;
mod peer_info;

pub use config::Config;

pub const VSS_SHARES_ID: &[u8] = b"vss_shares";
pub const VSS_COMMITMENTS_ID: &[u8] = b"vss_commitments";

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Transport(String),

    #[error("Residents length is exceeding the maximum, max: {0}")]
    ResidentsSize(u16),

    #[error("Vss error: {0}")]
    Vss(String),

    #[error("Channel is closed")]
    ChannelClosed,

    #[error("Timeout")]
    Timeout,

    #[error("Validation failed")]
    ValidationFailed,

    #[error("{0}")]
    Collector(#[from] collector::Error),

    #[error("{0}")]
    Distributor(#[from] distributor::Error),
}

pub struct JointFeldman<T: Transport + 'static, V: Vss + 'static> {
    transport: Arc<T>,
    config: Config,
    collector: Collector<T, V>,
    distributor: Distributor<T>,
    peers: Option<PeerRegistry>,
}

impl<T: Transport + 'static, V: Vss + 'static> JointFeldman<T, V> {
    pub async fn new(transport: Arc<T>, secret_key: SecretKey, config: Config) -> Result<Self> {
        let collector_config = collector::Config {
            timeout: config.timeout,
            gossipsub_topic: config.gossipsub_topic.clone(),
            query_channel_size: config.channel_size,
        };

        let collector = Collector::new(transport.clone(), secret_key, collector_config);
        let distributor = Distributor::new(transport.clone(), &config.gossipsub_topic);

        Ok(Self {
            transport,
            config,
            collector,
            distributor,
            peers: None,
        })
    }

    pub async fn set_peers(&mut self, peers: HashMap<libp2p::PeerId, PublicKey>) -> Result<()> {
        assert!(peers.len() > 1, "ids length must be greater than 1");
        assert!(
            peers.len() <= u16::MAX as usize,
            "ids length is exceeding the maximum"
        );

        let peers = PeerRegistry::new(peers);

        self.collector.stop();
        self.collector.start(peers.clone()).await?;
        self.peers = Some(peers);
        Ok(())
    }

    pub async fn generate(&self, id: Vec<u8>) -> Result<GenerateResult> {
        assert!(self.peers.is_some(), "Peers is empty");

        let peers = self
            .peers
            .as_ref()
            .expect("Peers is empty, it should be set");
        let nums: u16 = peers
            .len()
            .try_into()
            .expect("Peers length is exceeding the maximum, it should checked before");
        let mut shares = self.generate_shares(nums)?;
        let own_share = shares
            .shares
            .remove(
                &peers
                    .get_index(&self.transport.self_peer())
                    .expect("unreachable: own peer id"),
            )
            .expect("unreachable: own share not found");

        self.distributor
            .send_shares(id.clone(), peers, shares)
            .await?;

        let result = self.collector.query(id, own_share).await?;

        match result {
            CollectionResult::Success {
                own_shares,
                partial_public,
            } => {
                let secret = own_shares.into_iter().sum();
                let public = partial_public.values().cloned().sum();

                Ok(GenerateResult::Success {
                    secret,
                    public,
                    partial_public,
                })
            }
            CollectionResult::Failure { invalid_peers } => {
                Ok(GenerateResult::Failure { invalid_peers })
            }
        }
    }

    fn generate_shares(&self, nums: u16) -> Result<Shares> {
        let secret = Scalar::random(&self.config.crypto_scheme);
        let threshold = self.config.threshold_counter.call(nums);
        V::share(&secret, threshold, nums).map_err(|e| Error::Vss(e.to_string()))
    }
}

#[async_trait::async_trait]
impl<T: Transport + 'static, V: Vss + 'static> Dkg_ for JointFeldman<T, V> {
    type Error = Error;

    async fn set_peers(&mut self, peers: HashMap<libp2p::PeerId, PublicKey>) -> Result<()> {
        self.set_peers(peers).await
    }

    async fn generate(&self, id: Vec<u8>) -> Result<GenerateResult> {
        self.generate(id).await
    }
}
