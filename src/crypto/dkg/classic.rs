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
    elliptic::curves::{
        bls12_381::{g1::G1Point, scalar::FieldScalar},
        Curve, ECPoint, ECScalar, Point, Scalar,
    },
};
use libp2p::{gossipsub::MessageId, PeerId};
use log::error;
use thiserror::Error;
use tokio::{sync::mpsc::Receiver, task::JoinHandle, time::timeout};

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

#[derive(Debug)]
struct Signer<E: Curve> {
    secret: Scalar<E>,
    public_key: Vec<Point<E>>,
    threshold: u16,
    processing: HashMap<MessageId, Vec<G1Point>>,
}

impl<E: Curve> Signer<E> {
    pub fn new(secret: Scalar<E>, public_key: Vec<Point<E>>, threshold: u16) -> Self {
        let processing = HashMap::new();
        Self {
            secret,
            public_key,
            threshold,
            processing,
        }
    }

    pub fn sign<H: Digest + Clone>(&self, raw_msg: &[u8]) -> G1Point {
        let msg = H::new().chain(raw_msg).finalize();
        let hash = G1Point::hash_to_curve(&msg);
        let field_scalar = FieldScalar::from_bigint(&self.secret.to_bigint());
        hash.scalar_mul(&field_scalar)
    }

    pub fn update(&mut self, message_id: MessageId, signature: G1Point) -> Option<G1Point> {
        let signatures = self.processing.entry(message_id.clone()).or_default();
        signatures.push(signature);

        if signatures.len() == self.threshold as usize {
            let aggregated = Self::aggregate_signatures(signatures.drain(..));
            self.processing.remove(&message_id);
            Some(aggregated)
        } else {
            None
        }
    }

    fn aggregate_signatures(signatures: impl IntoIterator<Item = G1Point>) -> G1Point {
        signatures
            .into_iter()
            .reduce(|acc, sig| acc.add_point(&sig))
            .expect("signatures is empty")
    }
}

pub struct Classic<T: Transport + 'static> {
    #[allow(dead_code)]
    transport: Arc<T>,
    config: Config,
    handle: Option<JoinHandle<()>>,
}

impl<T: Transport + 'static> Classic<T> {
    pub fn new(transport: Arc<T>, config: Config) -> Self {
        let handle = None;
        Self {
            transport,
            config,
            handle,
        }
    }

    pub async fn start<E: Curve, H: Digest + Clone>(
        &mut self,
        self_peer: PeerId,
        other_peers: HashSet<PeerId>,
    ) -> Result<()> {
        let (signer, topic_rx) = self.init_signer::<E, H>(self_peer, other_peers).await?;
        let handle = self.receive::<E, H>(signer, topic_rx).await;
        self.handle = Some(handle);

        Ok(())
    }

    async fn init_signer<E: Curve, H: Digest + Clone>(
        &self,
        self_peer: PeerId,
        other_peers: HashSet<PeerId>,
    ) -> Result<(Signer<E>, Receiver<Message>)> {
        let mut topic_rx = self.listen_topic().await?;
        let mut peers_rx = self.listen_peers(other_peers.clone()).await?;
        let peers = Self::generate_full_peers(self_peer, other_peers)?;
        let num_peers = Self::calculate_num_peers(&peers);
        let threshold = (self.config.threshold_counter)(num_peers);
        let (vss, self_shares) = Self::generate_shares::<E, H>(threshold, num_peers);

        Self::publish_verifiable_ss(&self.transport, &vss).await?;
        Self::send_shares(&self.transport, &peers, &self_shares).await?;

        let self_index = Self::self_index(&self_peer, &peers);
        let collected = timeout(self.config.timeout, async {
            let nums = num_peers - 1;
            Self::collect_data::<E, H>(&mut topic_rx, &mut peers_rx, nums).await
        })
        .await
        .map_err(|_| Error::Timeout)??;

        let mut shares = Self::validate_data(&collected, self_index)?;
        shares.push(self_shares[(self_index - 1) as usize].clone());

        let secret = Self::construct_secret(&vss, &(1..=num_peers).collect::<Vec<u16>>(), &shares);
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

        let signer = Signer::new(secret, public_key, threshold);

        Ok((signer, topic_rx))
    }

    async fn listen_topic(&self) -> Result<Receiver<Message>> {
        self.transport
            .listen_on_topic(DKG_TOPIC)
            .await
            .map_err(Error::from)
    }

    async fn listen_peers(
        &self,
        peers: impl IntoIterator<Item = PeerId> + Send,
    ) -> Result<Receiver<Message>> {
        self.transport
            .listen_on_peers(peers)
            .await
            .map_err(Error::from)
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

    fn generate_shares<E: Curve, H: Digest + Clone>(
        threshold: u16,
        nums: u16,
    ) -> (VerifiableSS<E, H>, SecretShares<E>) {
        let secret = Scalar::random();
        let threshold = threshold - 1; // share need t - 1
        VerifiableSS::<E, H>::share(threshold, nums, &secret)
    }

    async fn publish_verifiable_ss<E: Curve, H: Digest + Clone>(
        transport: &Arc<T>,
        verifiable_ss: &VerifiableSS<E, H>,
    ) -> Result<()> {
        let bytes = serde_json::to_string(verifiable_ss)?;
        let request = Payload::DkgVSS(bytes.into());
        transport.publish(DKG_TOPIC, request).await?;
        Ok(())
    }

    async fn send_shares<E: Curve>(
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
            transport.request(*peer, request).await?;
        }
        Ok(())
    }

    async fn collect_data<E: Curve, H: Digest + Clone>(
        topic_rx: &mut Receiver<Message>,
        peers_rx: &mut Receiver<Message>,
        expected: u16,
    ) -> Result<HashMap<PeerId, PeerShare<E, H>>> {
        let mut collected: HashMap<PeerId, PeerShare<E, H>> =
            HashMap::with_capacity(expected as usize);
        let mut complete_count = 0;

        while complete_count < expected {
            tokio::select! {
                Some(msg) = topic_rx.recv() => {
                    if let Some((peer, vss_bytes)) = Payload::get_dkg_vss(msg) {
                        let vss: VerifiableSS<E, H> = serde_json::from_slice(&vss_bytes)?;
                        let entry = collected.entry(peer).or_insert_with(PeerShare::new);
                        if entry.update_v_ss(vss) {
                            complete_count += 1;
                        }
                    }
                }

                Some(msg) = peers_rx.recv() => {
                    if let Some((peer, scalar_bytes)) = Request::get_dkg_scalar(msg) {
                        let scalar = Scalar::from_bytes(scalar_bytes.as_slice())?;
                        let entry = collected.entry(peer).or_insert_with(PeerShare::new);
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

    fn validate_data<E: Curve, H: Digest + Clone>(
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

    fn construct_secret<E: Curve, H: Digest + Clone>(
        v_ss: &VerifiableSS<E, H>,
        indices: &[u16],
        shares: &[Scalar<E>],
    ) -> Scalar<E> {
        v_ss.reconstruct(indices, shares)
    }

    async fn receive<E: Curve, H: Digest + Clone>(
        &self,
        mut signer: Signer<E>,
        mut topic_rx: Receiver<Message>,
    ) -> JoinHandle<()> {
        let transport = self.transport.clone();

        tokio::spawn(async move {
            loop {
                match topic_rx.recv().await {
                    Some(msg) => {
                        if let Some((message_id, msg_to_sign)) = Payload::get_dkg_sign(msg) {
                            let signature = signer.sign::<H>(&msg_to_sign);
                            signer.update(message_id.clone(), signature);
                            let signature = signature.serialize_compressed().to_vec();
                            let response = Payload::DkgSignResponse {
                                message_id,
                                signature,
                            };
                            if let Err(e) = transport.publish(DKG_TOPIC, response).await {
                                error!("Failed to publish signature: {:?}", e);
                            };
                        }
                    }
                    None => {
                        error!("Channel is closed");
                        break;
                    }
                }
            }
        })
    }

    async fn stop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
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

        async fn send_v_ss(&self, topic_tx: &Sender<Message>) {
            let payload = Payload::DkgVSS(serde_json::to_string(&self.v_ss).unwrap().into());
            let msg = create_gossipsub_message(self.peer, DKG_TOPIC, payload);
            topic_tx.send(msg).await.unwrap();
        }

        async fn send_shares(&self, peer_tx: &Sender<Message>) {
            let share = &self.shares[self.target_index as usize - 1];
            let payload = Request::DkgScalar(share.to_bytes().to_vec());
            let msg = create_request_message(self.peer, payload);
            peer_tx.send(msg).await.unwrap();
        }
    }

    fn generate_peers(n: u16) -> HashSet<PeerId> {
        (0..n).map(|_| PeerId::random()).collect()
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

    fn create_request_message(peer: PeerId, payload: Request) -> Message {
        let payload = request_response::Payload::Request(payload);
        Message::RequestResponse(request_response::Message { peer, payload })
    }

    fn create_mock_transport(
        topic_rx: Receiver<Message>,
        peer_rx: Receiver<Message>,
    ) -> MockTransport {
        MockTransport::new()
            .with_listen_on_topic_cb_once(|_| topic_rx)
            .with_listen_on_peers_cb_once(|_| peer_rx)
            .with_publish_cb(|_, _| MessageId::from(MESSAGE_ID), 2)
            .with_request_cb(|_, _| (), 3)
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

    async fn create_classic(n: u16) -> (Classic<MockTransport>, PeerId, HashSet<PeerId>) {
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
        (Classic::new(transport, config), self_peer, other_peers)
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
        let mut classic = Classic::new(transport, config);

        let result = classic.start::<E, H>(self_peer, other_peers).await;

        assert!(
            result.is_ok(),
            "Failed to create classic DKG instance: {:?}",
            result.err()
        );
        assert!(
            classic.handle.is_some(),
            "Classic DKG instance is not running"
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

        let result = Classic::new(Arc::new(transport), config)
            .start::<E, H>(self_peer, other_peers)
            .await;

        assert!(
            result.is_err(),
            "Classic DKG instance should not be created due to timeout"
        );
    }

    #[tokio::test]
    async fn stop() {
        let (mut classic, self_peer, other_peers) = create_classic(NUM_PEERS).await;

        classic.start::<E, H>(self_peer, other_peers).await.unwrap();
        classic.stop().await;

        assert!(
            classic.handle.is_none(),
            "Classic DKG instance is still running"
        );
    }
}
