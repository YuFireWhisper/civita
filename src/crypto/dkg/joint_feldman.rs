use std::{collections::HashMap, sync::Arc};

use crate::{
    crypto::{
        dkg::{
            joint_feldman::{
                collector::{CollectionResult, Collector},
                distributor::Distributor,
                peer_registry::PeerRegistry,
            },
            Dkg_, GenerateResult,
        },
        keypair::{PublicKey, SecretKey},
        primitives::{
            algebra::{self, Point, Scalar},
            vss::{
                decrypted_share::{self, DecryptedShares},
                Vss,
            },
        },
    },
    network::transport::Transport,
};

mod collector;
mod config;
mod distributor;
mod peer_registry;

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

    #[error("Own index not found")]
    IndexNotFound,

    #[error("Own share not found")]
    OwnShareNotFound,

    #[error("Peers not set")]
    PeersNotSet,

    #[error("Decrypted shares error: {0}")]
    DecryptedShares(#[from] decrypted_share::Error),

    #[error("Algebra error: {0}")]
    Algebra(#[from] algebra::Error),
}

pub struct JointFeldman<T: Transport + 'static> {
    transport: Arc<T>,
    config: Config,
    collector: Collector<T>,
    distributor: Distributor<T>,
    peers: Option<PeerRegistry>,
}

impl<T: Transport + 'static> JointFeldman<T> {
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

        let peers_len = self.peers_len()?;
        let threshold = self.config.threshold_counter.call(peers_len);
        let (mut decrypted_shares, commitments) =
            Vss::share(&self.config.crypto_scheme, threshold, peers_len);
        let own_share = self.remove_own_share(&mut decrypted_shares)?;

        let peers = self.peers()?;
        self.distributor
            .send_shares(id.clone(), peers, &decrypted_shares, commitments)
            .await?;

        let result = self.collector.query(id, own_share).await?;

        match result {
            CollectionResult::Success {
                own_shares,
                partial_public,
            } => {
                let secret = Scalar::sum(own_shares.into_iter())?;
                let public = Point::sum(
                    partial_public
                        .values()
                        .map(|ps| ps.first().expect("Partial public share is empty").clone()),
                )?;

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

    fn peers_len(&self) -> Result<u16> {
        self.peers
            .as_ref()
            .map(|peers| peers.len())
            .ok_or(Error::PeersNotSet)
    }

    fn remove_own_share(&self, decrypted_shares: &mut DecryptedShares) -> Result<Scalar> {
        let peers = self.peers()?;
        let own_index = peers
            .get_index(&self.transport.self_peer())
            .ok_or(Error::IndexNotFound)?;
        decrypted_shares.remove(&own_index).map_err(Error::from)
    }

    fn peers(&self) -> Result<&PeerRegistry> {
        self.peers.as_ref().ok_or(Error::PeersNotSet)
    }
}

#[async_trait::async_trait]
impl<T: Transport + 'static> Dkg_ for JointFeldman<T> {
    type Error = Error;

    async fn set_peers(&mut self, peers: HashMap<libp2p::PeerId, PublicKey>) -> Result<()> {
        self.set_peers(peers).await
    }

    async fn generate(&self, id: Vec<u8>) -> Result<GenerateResult> {
        self.generate(id).await
    }
}
