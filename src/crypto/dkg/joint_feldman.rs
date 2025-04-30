use std::sync::Arc;

use crate::{
    crypto::{
        algebra::{self, Scalar},
        dkg::{
            joint_feldman::{
                collector::{event, Collector},
                distributor::Distributor,
            },
            Dkg, GenerateResult,
        },
        keypair::{PublicKey, SecretKey},
        vss::{decrypted_share, Vss},
    },
    utils::IndexedMap,
};

#[cfg(not(test))]
use crate::network::transport::Transport;

#[cfg(test)]
use crate::network::transport::MockTransport as Transport;

mod collector;
mod config;
mod distributor;

pub use config::Config;
use tokio::sync::{Mutex, MutexGuard};

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

    #[error("Lock is poisoned")]
    PoisonedLock,
}

pub struct JointFeldman {
    config: Config,
    collector: Collector,
    distributor: Distributor,
    peer_pks: Mutex<Option<IndexedMap<libp2p::PeerId, PublicKey>>>,
}

impl JointFeldman {
    pub fn new(transport: Arc<Transport>, secret_key: SecretKey, config: Config) -> Self {
        let collector_config = collector::Config {
            timeout: config.timeout,
            gossipsub_topic: config.gossipsub_topic.clone(),
            query_channel_size: config.channel_size,
        };

        let secret_key = Arc::new(secret_key);
        let collector = Collector::new(transport.clone(), secret_key, collector_config);
        let distributor = Distributor::new(transport, &config.gossipsub_topic);

        Self {
            config,
            collector,
            distributor,
            peer_pks: Mutex::new(None),
        }
    }

    pub async fn set_peers(
        &mut self,
        peer_pks: IndexedMap<libp2p::PeerId, PublicKey>,
    ) -> Result<()> {
        self.collector.stop();
        self.collector.start(peer_pks.clone()).await?;
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        self.peer_pks = Mutex::new(Some(peer_pks));
        Ok(())
    }

    pub async fn generate(&self, id: Vec<u8>) -> Result<GenerateResult> {
        let peers_len = self.peers_len().await?;
        let threshold = self.config.threshold_counter.call(peers_len);
        let (decrypted_shares, commitments) =
            Vss::share(&self.config.crypto_scheme, threshold, peers_len);

        let peer_pks = self.lock_peer_pks().await;
        self.distributor
            .send_shares(id.clone(), peer_pks, &decrypted_shares, commitments.clone())
            .await?;

        let result = self
            .collector
            .query(id, decrypted_shares, commitments)
            .await?;

        match result {
            event::Output::Success { shares, comms } => {
                let share = Scalar::sum(shares.iter())?;
                Ok(GenerateResult::Success {
                    secret: share,
                    partial_publics: comms,
                })
            }
            event::Output::Failure { invalid_peers } => {
                Ok(GenerateResult::Failure { invalid_peers })
            }
        }
    }

    async fn peers_len(&self) -> Result<u16> {
        self.lock_peer_pks()
            .await
            .as_ref()
            .map(|peer_pks| peer_pks.len())
            .ok_or(Error::PeersNotSet)
    }

    async fn lock_peer_pks(&self) -> MutexGuard<Option<IndexedMap<libp2p::PeerId, PublicKey>>> {
        self.peer_pks.lock().await
    }
}

#[async_trait::async_trait]
impl Dkg for JointFeldman {
    type Error = Error;

    async fn set_peers(&self, peers: IndexedMap<libp2p::PeerId, PublicKey>) -> Result<()> {
        self.set_peers(peers).await
    }

    async fn generate(&self, id: Vec<u8>) -> Result<GenerateResult> {
        self.generate(id).await
    }
}
