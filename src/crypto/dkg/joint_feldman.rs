use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    iter,
    sync::Arc,
};

use crate::{
    crypto::{
        core::element::{Public, Secret},
        dkg::{joint_feldman::collector::Collector, vss::Vss},
    },
    network::transport::{
        libp2p_transport::protocols::{gossipsub, request_response::payload::Request},
        Transport,
    },
};

mod collector;
mod config;

pub use config::Config;

const DKG_TOPIC: &str = "dkg";

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
    public_key: Option<PK>,
    secret_key: Option<SK>,
    collector: Collector<SK, PK, VSS>,
}

impl<T, SK, PK, VSS> JointFeldman<T, SK, PK, VSS>
where
    T: Transport + Send + Sync + 'static,
    SK: Secret,
    PK: Public,
    VSS: Vss<SK, PK>,
{
    pub fn new(transport: Arc<T>, config: Config) -> Self {
        let collector = Collector::new(config.timeout, transport.self_peer());

        Self {
            transport,
            config,
            public_key: None,
            secret_key: None,
            collector,
        }
    }

    pub async fn start_new_round(&mut self, other_ids: HashSet<libp2p::PeerId>) -> Result<()> {
        let topic_rx = self
            .transport
            .listen_on_topic(DKG_TOPIC)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        let peers_rx = self.transport.listen_on_peers(other_ids.clone()).await;

        let ids = Self::generate_full_peers(self.transport.self_peer(), other_ids)?;
        let num_ids: u16 = ids
            .len()
            .try_into()
            .map_err(|_| Error::ResidentsSize(u16::MAX))?;
        let threshold = self.config.threshold_counter.call(num_ids);
        let (shares, commitments) = Self::generate_shares(threshold, num_ids)?;

        self.publish_commitments(&commitments).await?;
        self.send_shares(&ids, &shares).await;

        let verified_pairs = self.collector.collect(topic_rx, peers_rx, &ids).await?;

        let own_share = shares
            .into_iter()
            .next()
            .expect("Share not found, it should be in the list");
        let own_commitments = commitments
            .into_iter()
            .next()
            .expect("Commitments not found, it should be in the list");

        let (full_shares, full_commitments) = verified_pairs
            .into_iter()
            .map(|pair| {
                let (share, commitments) = pair.into_components();
                let commitment = commitments
                    .into_iter()
                    .next()
                    .expect("Commitment not found");
                (share, commitment)
            })
            .chain(iter::once((own_share, own_commitments)))
            .collect::<(Vec<_>, Vec<_>)>();

        let private_key = full_shares.into_iter().sum();
        let public_key = full_commitments.into_iter().sum();

        self.secret_key = Some(private_key);
        self.public_key = Some(public_key);

        Ok(())
    }

    fn generate_full_peers(
        own_id: libp2p::PeerId,
        mut other_peer_ids: HashSet<libp2p::PeerId>,
    ) -> Result<HashMap<libp2p::PeerId, u16>> {
        other_peer_ids.insert(own_id);
        to_order_map(other_peer_ids, u16::MAX).map_err(|_| Error::ResidentsSize(u16::MAX))
    }

    fn generate_shares(threshold: u16, num_ids: u16) -> Result<(Vec<SK>, Vec<PK>)> {
        let secret = SK::random();
        VSS::share(&secret, threshold, num_ids).map_err(|e| Error::Vss(e.to_string()))
    }

    async fn publish_commitments(&self, commitments: &[PK]) -> Result<()> {
        let commitments_bytes = commitments
            .iter()
            .map(|commitment| commitment.to_vec())
            .collect::<Vec<_>>();
        let payload = gossipsub::Payload::DkgVSS_(commitments_bytes);
        self.transport
            .publish(DKG_TOPIC, payload)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        Ok(())
    }

    async fn send_shares(&self, ids: &HashMap<libp2p::PeerId, u16>, shares: &[SK]) {
        for (id, &index) in ids.iter() {
            let share = shares.get(index as usize - 1).expect("Share not found");
            let request = Request::DkgShare(share.to_vec());
            self.transport.request(id, request).await;
        }
    }
}

fn to_order_map<T, N, I>(iter: I, capacity: N) -> std::result::Result<HashMap<T, N>, ()>
where
    T: Ord + Hash,
    N: Copy + Ord + TryFrom<usize> + Into<usize>,
    I: IntoIterator<Item = T>,
{
    let cap = capacity.into();

    let mut items: Vec<T> = iter.into_iter().take(cap).collect();
    items.sort_unstable();

    let mut map = HashMap::with_capacity(items.len());

    for (i, item) in items.into_iter().enumerate() {
        match N::try_from(i + 1) {
            Ok(idx) => {
                map.insert(item, idx);
            }
            Err(_) => return Err(()),
        }
    }

    Ok(map)
}
