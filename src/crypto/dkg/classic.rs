use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    iter::once,
    sync::Arc,
};

use curv::elliptic::curves::Scalar;
use curv::{
    cryptographic_primitives::{
        hashing::Digest,
        secret_sharing::feldman_vss::{SecretShares, VerifiableSS},
    },
    elliptic::curves::Curve,
};
use libp2p::PeerId;
use log::error;
use sha2::Sha256;
use thiserror::Error;
use tokio::{
    sync::{mpsc::Receiver, oneshot::error::RecvError},
    time::timeout,
};

use crate::{
    crypto::dkg::{
        classic::{config::Config, keypair::Keypair, peer_share::PeerShare},
        Data, Dkg,
    },
    network::transport::{
        libp2p_transport::protocols::{
            gossipsub::{self, Payload},
            request_response::{self, payload::Request},
        },
        Transport,
    },
};

pub mod config;
pub mod curve_type;
pub mod factory;
pub mod keypair;
pub mod peer_share;
pub mod signature;

pub use curve_type::CurveType;
pub use signature::Signature;

type Result<T> = std::result::Result<T, Error>;

const DKG_TOPIC: &str = "dkg";

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Transport(String),

    #[error("Residents length is exceeding the maximum, max: {0}")]
    ResidentsSize(u16),

    #[error("Serde error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("Send error: {0}")]
    Send(String),

    #[error("Failed to receive: {0}")]
    Receive(#[from] RecvError),

    #[error("Curv deserialization error: {0}")]
    Deserialization(#[from] curv::elliptic::curves::error::DeserializationError),

    #[error("Validate share failed, peer: {0}")]
    ValidateShare(PeerId),

    #[error("Timeout")]
    Timeout,

    #[error("Channel is closed")]
    ChannelClosed,

    #[error("Datas is empty")]
    DataEmpty,

    #[error("Datas type is not classic")]
    DataTypeClassic,
}

pub struct Classic<E: Curve> {
    keypair: Keypair<E>,
}

impl<E: Curve> Classic<E> {
    pub async fn new<T: Transport>(
        transport: Arc<T>,
        self_peer: PeerId,
        other_peers: HashSet<PeerId>,
        config: Config,
    ) -> Result<Self> {
        let mut topic_rx = transport
            .listen_on_topic(DKG_TOPIC)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        let mut peers_rx = transport.listen_on_peers(other_peers.clone()).await;

        let peers = Self::generate_full_peers(self_peer, other_peers)?;
        let num_peers = Self::calculate_num_peers(&peers);
        let threshold = config.threshold_counter.call(num_peers);
        let (vss, self_shares) = Self::generate_shares::<Sha256>(threshold, num_peers);

        Self::publish_verifiable_ss(&transport, &vss).await?;
        Self::send_shares(&transport, &peers, &self_shares).await?;

        let self_index = Self::self_index(&self_peer, &peers);
        let collected = timeout(config.timeout, async {
            let nums = num_peers - 1;
            Self::collect_data::<Sha256>(&mut topic_rx, &mut peers_rx, nums).await
        })
        .await
        .map_err(|_| Error::Timeout)??;

        let mut shares = Self::validate_data(&collected, self_index)?;
        shares.push(self_shares[(self_index - 1) as usize].to_owned());

        let pub_keys = collected
            .into_values()
            .map(|peer_share| {
                peer_share
                    .vss_into()
                    .expect("VSS is missing")
                    .commitments
                    .into_iter()
                    .next()
                    .expect("Commitment is missing")
            })
            .chain(once(vss.commitments.into_iter().next().unwrap()))
            .collect::<Vec<_>>();
        let pub_key = pub_keys.iter().sum();
        let pri_key = shares.iter().sum();

        let keypair = Keypair::new(pub_key, pri_key);

        Ok(Self { keypair })
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
        let threshold = threshold - 1; // share need t - 1
        VerifiableSS::<E, H>::share(threshold, nums, &secret)
    }

    async fn publish_verifiable_ss<T: Transport, H: Digest + Clone>(
        transport: &Arc<T>,
        verifiable_ss: &VerifiableSS<E, H>,
    ) -> Result<()> {
        let bytes = serde_json::to_string(verifiable_ss)?;
        let request = Payload::DkgVSS(bytes.into());
        transport
            .publish(DKG_TOPIC, request)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        Ok(())
    }

    async fn send_shares<T: Transport>(
        transport: &Arc<T>,
        peers: &HashMap<PeerId, u16>,
        shares: &SecretShares<E>,
    ) -> Result<()> {
        for (peer, &index) in peers.iter() {
            let share = &shares.get(index as usize - 1).unwrap_or_else(|| {
                panic!(
                    "Invalid index, shares len: {}, index: {}",
                    shares.len(),
                    index
                )
            });
            let request = Request::DkgScalar(share.to_bytes().to_vec());
            transport.request(peer, request).await;
        }
        Ok(())
    }

    async fn collect_data<H: Digest + Clone>(
        topic_rx: &mut Receiver<gossipsub::Message>,
        peers_rx: &mut Receiver<request_response::Message>,
        expected: u16,
    ) -> Result<HashMap<PeerId, PeerShare<E, H>>> {
        let mut collected: HashMap<PeerId, PeerShare<E, H>> =
            HashMap::with_capacity(expected as usize);
        let mut complete_count = 0;

        while complete_count < expected {
            tokio::select! {
                Some(msg) = topic_rx.recv() => {
                    if let Payload::DkgVSS(vss_bytes) = msg.payload {
                        let peer = msg.source;
                        let vss: VerifiableSS<E, H> = serde_json::from_slice(&vss_bytes)?;
                        let entry = collected.entry(peer).or_default();
                        if entry.update_vss(vss) {
                            complete_count += 1;
                        }
                    }
                }

                Some(msg) = peers_rx.recv() => {
                    if let request_response::Payload::Request(Request::DkgScalar(scalar_bytes)) = msg.payload {
                        let scalar = Scalar::from_bytes(scalar_bytes.as_slice())?;
                        let entry = collected.entry(msg.peer).or_default();
                        if entry.update_scalar(scalar) {
                            complete_count += 1;
                        }
                    }
                }
                else => return Err(Error::ChannelClosed),
            }
        }
        Ok(collected)
    }

    fn self_index(self_peer: &PeerId, peers: &HashMap<PeerId, u16>) -> u16 {
        peers
            .get(self_peer)
            .copied()
            .expect("Self peer not found in peers map")
    }

    fn validate_data<H: Digest + Clone>(
        data: &HashMap<PeerId, PeerShare<E, H>>,
        self_index: u16,
    ) -> Result<Vec<Scalar<E>>> {
        data.iter()
            .map(|(peer, peer_share)| {
                if peer_share.validate(self_index) {
                    let scalar = peer_share
                        .scalar()
                        .expect("Scalar is missing, this should never happen");
                    Ok(scalar.clone())
                } else {
                    error!("Failed to validate share from peer: {:?}", peer);
                    Err(Error::ValidateShare(*peer))
                }
            })
            .collect()
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

impl<E: Curve> Dkg for Classic<E> {
    type Error = Error;

    fn sign(&self, seed: &[u8], msg: &[u8]) -> Data {
        self.keypair.sign(seed, msg).into()
    }

    fn validate(&self, msg: &[u8], sig: &Data) -> bool {
        sig.validate(msg, &self.keypair.public_key().to_bytes(true))
    }

    fn aggregate(&self, indices: &[u16], datas: Vec<Data>) -> Result<Data> {
        let sigs = datas
            .into_iter()
            .map(|data| match data {
                Data::Classic(sig) => Ok(sig.into()),
            })
            .collect::<Result<Vec<Signature<E>>>>()?;
        let sig = Signature::aggregate::<Sha256>(indices, sigs);
        Ok(Data::Classic(sig.into()))
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, sync::Arc};

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
        crypto::dkg::{
            classic::{config::Config, Classic, DKG_TOPIC},
            Dkg,
        },
        network::transport::{
            libp2p_transport::protocols::{
                gossipsub::{self, Payload},
                request_response::{self, payload::Request},
            },
            MockTransport,
        },
    };

    const NUM_PEERS: u16 = 3;
    const MESSAGE_ID: &str = "MESSAGE_ID";

    type E = Secp256k1;
    type H = Sha256;

    struct MockNode {
        peer: PeerId,
        v_ss: VerifiableSS<E, H>,
        shares: SecretShares<E>,
        target_index: u16,
    }

    impl MockNode {
        fn new(peer: PeerId, target_index: u16) -> Self {
            let scalar = Scalar::random();
            let threshold = threshold_counter(NUM_PEERS);
            let (v_ss, shares) = VerifiableSS::<E, H>::share(threshold - 1, NUM_PEERS, &scalar);

            Self {
                peer,
                v_ss,
                shares,
                target_index,
            }
        }

        async fn send_v_ss(&self, topic_tx: &Sender<gossipsub::Message>) {
            let payload = Payload::DkgVSS(serde_json::to_string(&self.v_ss).unwrap().into());
            let msg = create_gossipsub_message(self.peer, DKG_TOPIC, payload);
            topic_tx.send(msg).await.unwrap();
        }

        async fn send_shares(&self, peer_tx: &Sender<request_response::Message>) {
            let share = &self.shares[self.target_index as usize - 1];
            let payload = Request::DkgScalar(share.to_bytes().to_vec());
            let msg = create_request_message(self.peer, payload);
            peer_tx.send(msg).await.unwrap();
        }
    }

    fn generate_peers(n: u16) -> HashSet<PeerId> {
        (0..n).map(|_| PeerId::random()).collect()
    }

    fn create_gossipsub_message(
        source: PeerId,
        topic: &str,
        payload: Payload,
    ) -> gossipsub::Message {
        let message_id = MessageId::from(MESSAGE_ID);
        let sequence_number = 1;
        let topic = topic.to_string();
        gossipsub::Message {
            message_id,
            source,
            topic,
            payload,
            sequence_number,
        }
    }

    fn create_request_message(peer: PeerId, payload: Request) -> request_response::Message {
        let payload = request_response::Payload::Request(payload);
        request_response::Message { peer, payload }
    }

    fn create_mock_transport(
        topic_rx: Receiver<gossipsub::Message>,
        peer_rx: Receiver<request_response::Message>,
    ) -> MockTransport {
        let mut transport = MockTransport::new();
        transport
            .expect_listen_on_topic()
            .return_once(move |_| Ok(topic_rx));
        transport
            .expect_listen_on_peers()
            .return_once(move |_| peer_rx);
        transport
            .expect_publish()
            .returning(|_, _| Ok(MessageId::from(MESSAGE_ID)));
        transport.expect_request().returning(|_, _| {});

        transport
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
            timeout,
            threshold_counter,
            ..Default::default()
        }
    }

    fn threshold_counter(n: u16) -> u16 {
        (2 * n / 3) + 1
    }

    async fn create_classic(n: u16) -> Classic<E> {
        let (topic_tx, topic_rx) = channel((n - 1).into());
        let (peer_tx, peer_rx) = channel((n - 1).into());

        let mut peers: Vec<PeerId> = generate_peers(NUM_PEERS).into_iter().collect();
        peers.sort();

        for i in 0..n - 1 {
            let node = MockNode::new(peers[i as usize], NUM_PEERS);
            node.send_v_ss(&topic_tx).await;
            node.send_shares(&peer_tx).await;
        }

        let transport = Arc::new(create_mock_transport(topic_rx, peer_rx));
        let self_peer = peers[n as usize - 1];
        let mut other_peers: HashSet<_> = peers.into_iter().collect();
        other_peers.remove(&self_peer);
        let config = create_config();
        Classic::new(transport, self_peer, other_peers, config)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn create_success() {
        let (topic_tx, topic_rx) = channel((NUM_PEERS - 1).into());
        let (peer_tx, peer_rx) = channel((NUM_PEERS - 1).into());

        let mut peers: Vec<PeerId> = generate_peers(NUM_PEERS).into_iter().collect();
        peers.sort();

        for i in 0..NUM_PEERS - 1 {
            let node = MockNode::new(peers[i as usize], NUM_PEERS);
            node.send_v_ss(&topic_tx).await;
            node.send_shares(&peer_tx).await;
        }

        let transport = Arc::new(create_mock_transport(topic_rx, peer_rx));
        let self_peer = peers[NUM_PEERS as usize - 1];
        let mut other_peers: HashSet<_> = peers.into_iter().collect();
        other_peers.remove(&self_peer);
        let config = create_config();

        let result = Classic::<E>::new(transport, self_peer, other_peers, config).await;

        assert!(
            result.is_ok(),
            "Failed to create classic DKG instance: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn failed_when_timeout() {
        let (_, topic_rx) = channel((NUM_PEERS - 1).into());
        let (_, peer_rx) = channel((NUM_PEERS - 1).into());

        let transport = create_mock_transport(topic_rx, peer_rx);
        let peers: Vec<PeerId> = generate_peers(NUM_PEERS).into_iter().collect();
        let self_peer = peers[NUM_PEERS as usize - 1];
        let mut other_peers: HashSet<PeerId> = peers.into_iter().collect();
        other_peers.remove(&self_peer);
        let config = create_config_with_timeout(Duration::from_millis(1)); // Very short timeout

        let result = Classic::<E>::new(Arc::new(transport), self_peer, other_peers, config).await;

        assert!(
            result.is_err(),
            "Classic DKG instance should not be created due to timeout"
        );
    }

    #[tokio::test]
    async fn return_signature_invalid() {
        const SEED: &[u8] = b"SEED";
        const MESSAGE: &[u8] = b"MESSAGE";

        let classic = create_classic(NUM_PEERS).await;

        let result = classic.sign(SEED, MESSAGE);

        assert!(
            !classic.validate(MESSAGE, &result),
            "Signature should be invalid, because it is partial"
        );
    }
}
