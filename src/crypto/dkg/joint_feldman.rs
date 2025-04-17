use std::{collections::HashMap, sync::Arc};

use crate::{
    crypto::{
        dkg::{
            joint_feldman::{
                collector::{event, Collector},
                distributor::Distributor,
                peer_registry::PeerRegistry,
            },
            Dkg_, GenerateResult,
        },
        keypair::{PublicKey, SecretKey},
        primitives::{
            algebra::{self, Point, Scalar},
            vss::{
                decrypted_share::{self},
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

        let secret_key = Arc::new(secret_key);
        let collector = Collector::new(transport.clone(), secret_key, collector_config);
        let distributor = Distributor::new(transport, &config.gossipsub_topic);

        Ok(Self {
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
        let (decrypted_shares, commitments) =
            Vss::share(&self.config.crypto_scheme, threshold, peers_len);

        let peers = self.peers()?;
        self.distributor
            .send_shares(id.clone(), peers, &decrypted_shares, commitments.clone())
            .await?;

        let result = self
            .collector
            .query(id, decrypted_shares, commitments)
            .await?;

        match result {
            event::Output::Success { shares, comms } => {
                let share = Scalar::sum(shares.into_iter())?;
                let public = Point::sum(
                    comms
                        .values()
                        .map(|p| p.first().expect("Point is not empty").clone()),
                )
                .map_err(Error::from)?;

                Ok(GenerateResult::Success {
                    secret: share,
                    public,
                    partial_public: comms,
                })
            }
            event::Output::Failure { invalid_peers } => {
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
