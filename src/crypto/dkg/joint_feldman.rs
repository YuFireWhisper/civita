use std::{collections::HashSet, iter, sync::Arc};

use crate::{
    crypto::{
        dkg::{
            joint_feldman::{collector::Collector, distributor::Distributor},
            Dkg_, GenerateOutput,
        },
        primitives::{
            algebra::element::{Public, Secret},
            vss::Vss,
        },
    },
    network::transport::Transport,
};

mod collector;
mod config;
mod distributor;

pub use config::Config;

const DKG_TOPIC: &str = "dkg";
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

pub struct JointFeldman<T, SK, PK, VSS>
where
    T: Transport + Send + Sync + 'static,
    SK: Secret,
    PK: Public,
    VSS: Vss<SK, PK>,
{
    transport: Arc<T>,
    config: Config,
    collector: Collector<SK, PK, VSS>,
    distributor: Distributor<T, SK, PK>,
    peers: Option<Vec<libp2p::PeerId>>,
    own_index: Option<u16>,
}

impl<T, SK, PK, VSS> JointFeldman<T, SK, PK, VSS>
where
    T: Transport + Send + Sync + 'static,
    SK: Secret + 'static,
    PK: Public + 'static,
    VSS: Vss<SK, PK> + 'static,
{
    pub async fn new(transport: Arc<T>, config: Config) -> Result<Self> {
        let collector = Collector::new(
            transport.self_peer(),
            config.timeout,
            config.threshold_counter,
        );
        let distributor = Distributor::new(transport.clone(), DKG_TOPIC);

        Ok(Self {
            transport,
            config,
            collector,
            distributor,
            peers: None,
            own_index: None,
        })
    }

    pub async fn set_peers(&mut self, peers: HashSet<libp2p::PeerId>) -> Result<()> {
        assert!(peers.len() > 1, "ids length must be greater than 1");
        assert!(
            peers.len() <= u16::MAX as usize,
            "ids length is exceeding the maximum"
        );

        let topic_rx = self
            .transport
            .listen_on_topic(DKG_TOPIC)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        let peers_rx = self.transport.listen_on_peers(peers.clone()).await;
        let mut peers = peers.into_iter().collect::<Vec<_>>();
        peers.sort_unstable();

        let own_index = peers
            .iter()
            .position(|peer| peer == &self.transport.self_peer())
            .expect("Self peer not found in peers list");

        self.collector.stop();
        self.collector.start(topic_rx, peers_rx, peers.clone());
        self.peers = Some(peers);
        self.own_index = Some(own_index as u16 + 1);
        Ok(())
    }

    pub async fn generate(&self, id: Vec<u8>) -> Result<GenerateOutput<SK, PK>> {
        assert!(self.peers.is_some(), "Peers is empty");

        let peers = self
            .peers
            .as_ref()
            .expect("Peers is empty, it should be set");
        let nums: u16 = peers
            .len()
            .try_into()
            .expect("Peers length is exceeding the maximum, it should checked before");
        let (mut shares, commitments) = self.generate_shares(nums)?;
        let own_shares = shares.remove((self.own_index.expect("Own index is empty") - 1) as usize);

        self.distributor
            .send_shares(peers, VSS_SHARES_ID, &shares)
            .await;
        self.distributor
            .publish_commitments(VSS_COMMITMENTS_ID, &commitments)
            .await?;

        let result = self.collector.query(id).await?;
        let mut full_shares = result.shares;
        full_shares.push(own_shares);
        let full_commitments = result
            .commitments
            .into_iter()
            .map(|commitment| commitment.into_iter().next().expect("Commitment not found"))
            .chain(iter::once(
                commitments
                    .into_iter()
                    .next()
                    .expect("Commitment not found"),
            ))
            .collect::<Vec<_>>();

        let secret = full_shares.into_iter().sum();
        let public = full_commitments.into_iter().sum();

        Ok(GenerateOutput {
            secret,
            public,
            participants: result.participants,
        })
    }

    fn generate_shares(&self, nums: u16) -> Result<(Vec<SK>, Vec<PK>)> {
        let secret = SK::random();
        let threshold = self.config.threshold_counter.call(nums);
        VSS::share(&secret, threshold, nums).map_err(|e| Error::Vss(e.to_string()))
    }
}

#[async_trait::async_trait]
impl<T, SK, PK, VSS> Dkg_<SK, PK> for JointFeldman<T, SK, PK, VSS>
where
    T: Transport + Send + Sync + 'static,
    SK: Secret + 'static,
    PK: Public + 'static,
    VSS: Vss<SK, PK> + 'static,
{
    type Error = Error;

    async fn set_peers(&mut self, peers: HashSet<libp2p::PeerId>) -> Result<()> {
        self.set_peers(peers).await
    }

    async fn generate(&self, id: Vec<u8>) -> Result<GenerateOutput<SK, PK>> {
        self.generate(id).await
    }
}
