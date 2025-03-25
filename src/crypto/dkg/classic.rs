pub mod config;

use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    sync::Arc,
};

use curv::{
    cryptographic_primitives::{
        hashing::Digest,
        secret_sharing::feldman_vss::{SecretShares, VerifiableSS},
    },
    elliptic::curves::{Curve, Point, Scalar},
};
use libp2p::PeerId;
use log::error;
use thiserror::Error;
use tokio::{sync::mpsc::Receiver, time::timeout};

use crate::{
    crypto::dkg::classic::config::Config,
    network::transport::{
        libp2p_transport::{
            message::Message,
            protocols::{gossipsub::Payload, request_response::payload::Request},
        },
        Transport,
    },
};

const DKG_TOPIC: &str = "dkg";

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Transport(#[from] crate::network::transport::Error),
    #[error("Residents length is exceeding the maximum, max: {0}")]
    ResidentsSize(u16),
    #[error("Serde error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("Curv deserialization error: {0}")]
    Deserialization(#[from] curv::elliptic::curves::error::DeserializationError),
    #[error("Validate share failed, peer: {0}")]
    ValidateShare(PeerId),
    #[error("Timeout")]
    Timeout,
    #[error("Channel is closed")]
    ChannelClosed,
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
struct PeerShare<E: Curve, H: Digest + Clone> {
    vss: Option<VerifiableSS<E, H>>,
    scalar: Option<Scalar<E>>,
}

impl<E: Curve, H: Digest + Clone> PeerShare<E, H> {
    pub fn new() -> Self {
        let vss = None;
        let scalar = None;
        Self { vss, scalar }
    }

    pub fn update_v_ss(&mut self, v_ss: VerifiableSS<E, H>) -> bool {
        self.vss = Some(v_ss);

        self.is_complete()
    }

    pub fn update_scalar(&mut self, scalar: Scalar<E>) -> bool {
        self.scalar = Some(scalar);

        self.is_complete()
    }

    fn is_complete(&self) -> bool {
        self.vss.is_some() && self.scalar.is_some()
    }

    pub fn validate(&self, index: u16) -> bool {
        assert!(
            self.is_complete(),
            "PeerShare is not complete, please update it before validation"
        );

        let v_ss = self
            .vss
            .as_ref()
            .expect("VSS is missing, this should never happen");
        let scalar = self
            .scalar
            .as_ref()
            .expect("Scalar is missing, this should never happen");

        v_ss.validate_share(scalar, index).is_ok()
    }
}

pub struct Classic<T: Transport, E: Curve> {
    #[allow(dead_code)]
    transport: Arc<T>,
    #[allow(dead_code)]
    secret: Scalar<E>,
    #[allow(dead_code)]
    public_key: Vec<Point<E>>,
}

impl<T: Transport, E: Curve> Classic<T, E> {
    pub async fn new<H: Digest + Clone>(
        transport: Arc<T>,
        self_peer: PeerId,
        other_peers: HashSet<PeerId>,
        config: Config,
    ) -> Result<Self> {
        let vss_rx = Self::listen_verifiable_ss(transport.clone()).await?;
        let share_rx = Self::listen_share(transport.clone(), other_peers.clone()).await?;

        let peers = Self::generate_full_peers(self_peer, other_peers)?;
        let num_peers = Self::calculate_num_peers(&peers);
        let threshold = (config.threshold_counter)(num_peers);
        let (verifiable_ss, secret_shares) = Self::generate_shares::<H>(threshold - 1, num_peers);

        Self::publish_verifiable_ss(transport.clone(), verifiable_ss.clone()).await?;
        Self::send_shares(transport.clone(), &peers, secret_shares.clone()).await?;

        let collected = timeout(config.timeout, async {
            Self::collect_data::<H>(share_rx, vss_rx, num_peers - 1).await
        })
        .await
        .map_err(|_| Error::Timeout)??;
        let self_index = Self::self_index(self_peer, &peers);
        let mut shares = Self::validate_data(&collected, self_index)?;
        shares.push(secret_shares[(self_index - 1) as usize].clone());
        let secret = Self::construct_secret(
            &verifiable_ss,
            &(1..=num_peers).collect::<Vec<u16>>(),
            &shares,
        );
        let public_key: Vec<_> = collected
            .into_values()
            .map(|peer_share| {
                peer_share
                    .vss
                    .expect("VSS is missing, this should never happen")
                    .commitments
                    .into_iter()
                    .next()
                    .expect("Commitment is missing, this should never happen")
            })
            .collect();

        Ok(Self {
            transport,
            secret,
            public_key,
        })
    }

    async fn listen_verifiable_ss(transport: Arc<T>) -> Result<Receiver<Message>> {
        transport
            .listen_on_topic(DKG_TOPIC)
            .await
            .map_err(Error::from)
    }

    async fn listen_share(transport: Arc<T>, peers: HashSet<PeerId>) -> Result<Receiver<Message>> {
        transport.listen_on_peers(peers).await.map_err(Error::from)
    }

    fn generate_full_peers(
        self_peer_id: PeerId,
        mut other_peer_ids: HashSet<PeerId>,
    ) -> Result<HashMap<PeerId, u16>> {
        other_peer_ids.insert(self_peer_id);
        to_order_map(other_peer_ids, u16::MAX).map_err(|_| Error::ResidentsSize(u16::MAX))
    }

    fn calculate_num_peers(peers: &HashMap<PeerId, u16>) -> u16 {
        peers
            .len()
            .try_into()
            .expect("Failed to convert usize to u16, this should never happen")
    }

    fn generate_shares<H: Digest + Clone>(
        threshold: u16,
        nums: u16,
    ) -> (VerifiableSS<E, H>, SecretShares<E>) {
        let secret = Scalar::random();
        VerifiableSS::<E, H>::share(threshold, nums, &secret)
    }

    async fn publish_verifiable_ss<H: Digest + Clone>(
        transport: Arc<T>,
        verifiable_ss: VerifiableSS<E, H>,
    ) -> Result<()> {
        let bytes = serde_json::to_string(&verifiable_ss)?;
        let request = Payload::DkgVSS(bytes.into());
        transport.publish(DKG_TOPIC, request).await?;
        Ok(())
    }

    async fn send_shares(
        transport: Arc<T>,
        peers: &HashMap<PeerId, u16>,
        shares: SecretShares<E>,
    ) -> Result<()> {
        for ((peer_id, _), share) in peers.iter().zip(shares.iter()) {
            let request = Request::DkgScalar(share.to_bytes().to_vec());
            transport.request(*peer_id, request).await?;
        }
        Ok(())
    }

    async fn collect_data<H: Digest + Clone>(
        mut scalar_rx: Receiver<Message>,
        mut vss_rx: Receiver<Message>,
        expected: u16,
    ) -> Result<HashMap<PeerId, PeerShare<E, H>>> {
        let mut collected: HashMap<PeerId, PeerShare<E, H>> =
            HashMap::with_capacity(expected as usize);
        let mut complete_count = 0;

        while complete_count < expected {
            tokio::select! {
                Some(msg) = scalar_rx.recv() => {
                    if let Some((peer, scalar_bytes)) = Request::get_dkg_scalar(msg) {
                        let scalar = Scalar::from_bytes(scalar_bytes.as_slice())?;
                        let entry = collected.entry(peer).or_insert_with(PeerShare::new);
                        if entry.update_scalar(scalar) {
                            complete_count += 1;
                        }
                    }
                }
                Some(msg) = vss_rx.recv() => {
                    if let Some((peer, vss_bytes)) = Payload::get_dkg_vss(msg) {
                        let vss: VerifiableSS<E, H> = serde_json::from_slice(&vss_bytes)?;
                        let entry = collected.entry(peer).or_insert_with(PeerShare::new);
                        if entry.update_v_ss(vss) {
                            complete_count += 1;
                        }
                    }
                }
                else => return Err(Error::ChannelClosed),
            }
        }
        Ok(collected)
    }

    fn self_index(self_peer: PeerId, peers: &HashMap<PeerId, u16>) -> u16 {
        peers.get(&self_peer).copied().unwrap_or_default()
    }

    fn validate_data<H: Digest + Clone>(
        data: &HashMap<PeerId, PeerShare<E, H>>,
        self_index: u16,
    ) -> Result<Vec<Scalar<E>>> {
        data.iter()
            .map(|(peer, peer_share)| {
                if peer_share.validate(self_index) {
                    let scalar = peer_share
                        .scalar
                        .as_ref()
                        .expect("Scalar is missing, this should never happen");
                    Ok(scalar.clone())
                } else {
                    error!("Failed to validate share from peer: {:?}", peer);
                    Err(Error::ValidateShare(*peer))
                }
            })
            .collect()
    }

    fn construct_secret<H: Digest + Clone>(
        v_ss: &VerifiableSS<E, H>,
        indices: &[u16],
        shares: &[Scalar<E>],
    ) -> Scalar<E> {
        v_ss.reconstruct(indices, shares)
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

#[cfg(test)]
mod tests {

    use std::{
        collections::{HashMap, HashSet},
        sync::Arc,
    };

    use curv::{
        cryptographic_primitives::secret_sharing::feldman_vss::{SecretShares, VerifiableSS},
        elliptic::curves::{Scalar, Secp256k1},
    };
    use libp2p::{gossipsub::MessageId, PeerId};
    use sha2::Sha256;
    use tokio::{
        sync::mpsc::{channel, Receiver, Sender},
        time::Duration,
    };

    use crate::{
        crypto::dkg::classic::{config::Config, Classic, DKG_TOPIC},
        network::transport::libp2p_transport::{
            message::Message,
            mock_transport::MockTransport,
            protocols::{
                gossipsub::{self, Payload},
                request_response::{self, payload::Request},
            },
        },
    };

    const NUM_PEERS: u16 = 3;
    const MESSAGE_ID: &str = "MESSAGE_ID";

    type E = Secp256k1;
    type H = Sha256;

    fn generate_peers(n: u16) -> (PeerId, HashSet<PeerId>) {
        let self_peer = PeerId::random();
        let mut other_peers = HashSet::with_capacity(n as usize);
        for _ in 0..n - 1 {
            other_peers.insert(PeerId::random());
        }
        (self_peer, other_peers)
    }

    fn generate_shares(
        threshold: u16,
        peers: HashSet<PeerId>,
    ) -> (
        HashMap<PeerId, VerifiableSS<E, H>>,
        HashMap<PeerId, SecretShares<E>>,
    ) {
        let mut v_ss_map: HashMap<PeerId, VerifiableSS<E, H>> = HashMap::with_capacity(peers.len());
        let mut shares_map: HashMap<PeerId, SecretShares<E>> = HashMap::with_capacity(peers.len());
        let len = peers.len() as u16;

        for peer in peers.into_iter() {
            let (v_ss, shares) = VerifiableSS::<E, H>::share(threshold, len, &Scalar::random());
            v_ss_map.insert(peer, v_ss);
            shares_map.insert(peer, shares);
        }

        (v_ss_map, shares_map)
    }

    fn get_self_index(self_peer: PeerId, peers: HashSet<PeerId>) -> u16 {
        let mut sorted_peers: Vec<PeerId> = peers.into_iter().collect();
        sorted_peers.sort();
        match sorted_peers.binary_search(&self_peer) {
            Ok(index) => (index + 1) as u16,
            Err(_) => panic!("Self peer not found in peers list"),
        }
    }

    async fn send_v_sss(
        topic_tx: &Sender<Message>,
        self_peer: PeerId,
        v_ss_map: HashMap<PeerId, VerifiableSS<E, H>>,
    ) {
        for (peer, v_ss) in v_ss_map.into_iter() {
            if peer == self_peer {
                continue;
            }
            let payload = Payload::DkgVSS(serde_json::to_string(&v_ss).unwrap().into());
            let msg = create_gossipsub_message(peer, DKG_TOPIC, payload);
            topic_tx.send(msg).await.unwrap();
        }
    }

    fn create_gossipsub_message(source: PeerId, topic: &str, payload: Payload) -> Message {
        let message_id = MessageId::from(MESSAGE_ID);
        let sequence_number = 1;
        let topic = topic.to_string();
        Message::Gossipsub(gossipsub::Message {
            message_id,
            source,
            topic,
            payload,
            sequence_number,
        })
    }

    async fn send_shares(
        topic_tx: &Sender<Message>,
        self_peer: PeerId,
        shares_map: HashMap<PeerId, SecretShares<E>>,
    ) {
        let peers: HashSet<PeerId> = shares_map.keys().copied().collect();
        let index = get_self_index(self_peer, peers) - 1;

        for (peer, shares) in shares_map.into_iter() {
            if peer == self_peer {
                continue;
            }
            let payload = Request::DkgScalar(shares[index as usize].to_bytes().to_vec());
            let msg = create_request_message(peer, payload);
            topic_tx.send(msg).await.unwrap();
        }
    }

    fn create_request_message(peer: PeerId, payload: Request) -> Message {
        let payload = request_response::Payload::Request(payload);
        Message::RequestResponse(request_response::Message { peer, payload })
    }

    fn create_mock_transport(
        topic_rx: Receiver<Message>,
        peer_rx: Receiver<Message>,
    ) -> MockTransport {
        MockTransport::new()
            .with_topic_rx(topic_rx)
            .with_peer_rx(peer_rx)
    }

    fn create_config() -> Config {
        let threshold_counter = Box::new(threshold_counter);
        Config {
            threshold_counter,
            ..Default::default()
        }
    }

    fn create_config_with_timeout(timeout: Duration) -> Config {
        let threshold_counter = Box::new(threshold_counter);
        Config {
            threshold_counter,
            timeout,
        }
    }

    fn threshold_counter(n: u16) -> u16 {
        (2 * n / 3) + 1
    }

    #[tokio::test]
    async fn create_success() {
        let (topic_tx, topic_rx) = channel((NUM_PEERS - 1).into());
        let (peer_tx, peer_rx) = channel((NUM_PEERS - 1).into());

        let (self_peer, mut other_peers) = generate_peers(NUM_PEERS);
        other_peers.insert(self_peer);
        let all_peers = other_peers.clone();
        let (v_ss_map, shares_map) =
            generate_shares(threshold_counter(NUM_PEERS) - 1, all_peers.clone());

        send_v_sss(&topic_tx, self_peer, v_ss_map).await;
        send_shares(&peer_tx, self_peer, shares_map).await;

        let transport = create_mock_transport(topic_rx, peer_rx);
        let config = create_config();

        other_peers.remove(&self_peer);
        let classic =
            Classic::<_, E>::new::<H>(Arc::new(transport), self_peer, other_peers, config).await;

        assert!(
            classic.is_ok(),
            "Failed to create classic DKG instance: {:?}",
            classic.err()
        );
    }

    #[tokio::test]
    async fn failed_when_timeout() {
        let (_, topic_rx) = channel((NUM_PEERS - 1).into());
        let (_, peer_rx) = channel((NUM_PEERS - 1).into());

        let transport = create_mock_transport(topic_rx, peer_rx);
        let (self_peer, other_peers) = generate_peers(NUM_PEERS);
        let config = create_config_with_timeout(Duration::from_millis(1)); // Very short timeout

        let classic =
            Classic::<_, E>::new::<H>(Arc::new(transport), self_peer, other_peers, config).await;

        assert!(
            classic.is_err(),
            "Classic DKG instance should not be created due to timeout"
        );
    }
}
