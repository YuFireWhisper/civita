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
use tokio::sync::mpsc::Receiver;

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
}

type Result<T> = std::result::Result<T, Error>;
type DkgSharePair<E, H> = (Option<VerifiableSS<E, H>>, Option<Scalar<E>>);

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
        let v_ss_rx = Self::listen_verifiable_ss(transport.clone()).await?;
        let share_rx = Self::listen_share(transport.clone(), other_peers.clone()).await?;

        let peers = Self::generate_full_peers(self_peer, other_peers)?;
        let num_peers = Self::calculate_num_peers(&peers);
        let threshold = (config.threshold_counter)(num_peers) - 1;
        let (verifiable_ss, secret_shares) = Self::generate_shares::<H>(threshold, num_peers);

        Self::publish_verifiable_ss(transport.clone(), verifiable_ss.clone()).await?;
        Self::send_shares(transport.clone(), peers.clone(), secret_shares.clone()).await?;

        let data = Self::collect_data::<H>(share_rx, v_ss_rx, num_peers - 1).await?;
        let self_index = Self::self_index(self_peer, &peers);
        let mut shares = Self::validate_data(&data, self_index)?;
        shares.push(secret_shares[(self_index - 1) as usize].clone());
        let secret = Self::construct_secret(
            &verifiable_ss,
            &(1..=num_peers).collect::<Vec<u16>>(),
            &shares,
        );
        let public_key: Vec<_> = data
            .into_iter()
            .map(|(_, (v_ss, _))| v_ss.commitments.into_iter().next().unwrap())
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
        peers: HashMap<PeerId, u16>,
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
        mut v_ss_rx: Receiver<Message>,
        nums: u16,
    ) -> Result<HashMap<PeerId, (VerifiableSS<E, H>, Scalar<E>)>> {
        let mut collected = HashMap::with_capacity(nums as usize);
        let mut complete_count = 0;

        while complete_count < nums {
            tokio::select! {
                Some(msg) = scalar_rx.recv() => {
                    if let Some((peer, scalar)) = Request::get_dkg_scalar(msg) {
                        let scalar = Scalar::from_bytes(scalar.as_slice())?;
                        complete_count += Self::update_entry(&mut collected, peer, Some(scalar), None);
                    }
                }
                Some(msg) = v_ss_rx.recv() => {
                    if let Some((peer, v_ss)) = Payload::get_dkg_vss(msg) {
                        let v_ss: VerifiableSS<E, H> = serde_json::from_slice(&v_ss)?;
                        complete_count += Self::update_entry(&mut collected, peer, None, Some(v_ss));
                    }
                }
            }
        }

        Ok(collected
            .into_iter()
            .map(|(peer, (v_ss, scalar))| (peer, (v_ss.unwrap(), scalar.unwrap())))
            .collect())
    }

    fn update_entry<H: Digest + Clone>(
        map: &mut HashMap<PeerId, DkgSharePair<E, H>>,
        peer: PeerId,
        scalar: Option<Scalar<E>>,
        v_ss: Option<VerifiableSS<E, H>>,
    ) -> u16 {
        let entry = map.entry(peer).or_insert((None, None));
        let was_complete = entry.0.is_some() && entry.1.is_some();

        if let Some(scalar) = scalar {
            entry.1 = Some(scalar);
        }
        if let Some(v_ss) = v_ss {
            entry.0 = Some(v_ss);
        }

        let is_complete_now = entry.0.is_some() && entry.1.is_some();
        (!was_complete && is_complete_now) as u16
    }

    fn self_index(self_peer: PeerId, peers: &HashMap<PeerId, u16>) -> u16 {
        peers.get(&self_peer).copied().unwrap_or_default()
    }

    fn validate_data<H: Digest + Clone>(
        data: &HashMap<PeerId, (VerifiableSS<E, H>, Scalar<E>)>,
        self_index: u16,
    ) -> Result<Vec<Scalar<E>>> {
        data.iter()
            .map(|(peer, (v_ss, scalar))| {
                v_ss.validate_share(scalar, self_index)
                    .map(|_| scalar.clone())
                    .map_err(|_| Error::ValidateShare(*peer))
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
    use tokio::sync::mpsc::{channel, Receiver, Sender};

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
}
