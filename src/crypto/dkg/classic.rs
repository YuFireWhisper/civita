pub mod config;
pub mod keypair;
pub mod peer_share;
pub mod signature;
pub mod signer;

pub use signature::Signature;

use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    iter::once,
    sync::Arc,
};

use curv::elliptic::curves::{Point, Scalar};
use curv::{
    cryptographic_primitives::{
        hashing::Digest,
        secret_sharing::feldman_vss::{SecretShares, VerifiableSS},
    },
    elliptic::curves::Curve,
};
use libp2p::{gossipsub::MessageId, PeerId};
use log::error;
use thiserror::Error;
use tokio::{
    sync::{
        mpsc::{channel, Receiver, Sender},
        oneshot::{self, error::RecvError},
        Mutex,
    },
    task::JoinHandle,
    time::timeout,
};

use crate::{
    crypto::dkg::classic::{
        config::Config,
        keypair::{Keypair, PublicKey, Secret},
        peer_share::PeerShare,
        signer::Signer,
    },
    network::transport::{
        libp2p_transport::{
            message::Message,
            protocols::{gossipsub::Payload, request_response::payload::Request},
        },
        Transport,
    },
};

type Result<T> = std::result::Result<T, Error>;
type ToSelfTxType<E> = (MessageId, Vec<u8>, oneshot::Sender<Signature<E>>);

const DKG_TOPIC: &str = "dkg";

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Transport(#[from] crate::network::transport::Error),
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
}

pub struct Classic<T: Transport + 'static, E: Curve> {
    transport: Arc<T>,
    config: Config,
    handle: Option<JoinHandle<()>>,
    to_self_tx: Option<Sender<ToSelfTxType<E>>>,
    completed: Arc<Mutex<HashMap<Vec<u8>, Signature<E>>>>,
    peer: Option<PeerId>,
    pub_key: Option<PublicKey<E>>,
}

impl<T: Transport + 'static, E: Curve> Classic<T, E> {
    pub fn new(transport: Arc<T>, config: Config) -> Self {
        let handle = None;
        let to_self_tx = None;
        let completed = Arc::new(Mutex::new(HashMap::new()));
        let peer = None;
        let pub_key = None;
        Self {
            transport,
            config,
            handle,
            to_self_tx,
            completed,
            peer,
            pub_key,
        }
    }

    pub async fn start<H: Digest + Clone>(
        &mut self,
        self_peer: PeerId,
        other_peers: HashSet<PeerId>,
    ) -> Result<()> {
        self.peer = Some(self_peer);
        let (signer, topic_rx) = self.init_signer::<H>(self_peer, other_peers).await?;
        let handle = self.receive::<H>(signer, topic_rx).await;
        self.handle = Some(handle);

        Ok(())
    }

    async fn init_signer<H: Digest + Clone>(
        &mut self,
        self_peer: PeerId,
        other_peers: HashSet<PeerId>,
    ) -> Result<(Signer<E>, Receiver<Message>)> {
        let mut topic_rx = self.listen_topic().await?;
        let mut peers_rx = self.listen_peers(other_peers.clone()).await?;
        let peers = Self::generate_full_peers(self_peer, other_peers)?;
        let num_peers = Self::calculate_num_peers(&peers);
        let threshold = self.config.threshold_counter.call(num_peers);
        let (vss, self_shares) = Self::generate_shares::<H>(threshold, num_peers);

        Self::publish_verifiable_ss(&self.transport, &vss).await?;
        Self::send_shares(&self.transport, &peers, &self_shares).await?;

        let self_index = Self::self_index(&self_peer, &peers);
        let collected = timeout(self.config.timeout, async {
            let nums = num_peers - 1;
            Self::collect_data::<H>(&mut topic_rx, &mut peers_rx, nums).await
        })
        .await
        .map_err(|_| Error::Timeout)??;

        let mut shares = Self::validate_data(&collected, self_index)?;
        shares.push(self_shares[(self_index - 1) as usize].clone().into());

        let private_key = Secret::sum(shares.into_iter());
        let points = collected
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
            .collect::<Vec<Point<E>>>();
        let keypair = Keypair::new(points, private_key);
        let pub_key = keypair.public_key().clone();
        self.pub_key = Some(pub_key.clone());

        let mut signer = Signer::new(keypair, self.config.threshold_counter.clone_box());
        signer.add_peers(peers);

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

    fn generate_shares<H: Digest + Clone>(
        threshold: u16,
        nums: u16,
    ) -> (VerifiableSS<E, H>, SecretShares<E>) {
        let secret = Scalar::random();
        let threshold = threshold - 1; // share need t - 1
        VerifiableSS::<E, H>::share(threshold, nums, &secret)
    }

    async fn publish_verifiable_ss<H: Digest + Clone>(
        transport: &Arc<T>,
        verifiable_ss: &VerifiableSS<E, H>,
    ) -> Result<()> {
        let bytes = serde_json::to_string(verifiable_ss)?;
        let request = Payload::DkgVSS(bytes.into());
        transport.publish(DKG_TOPIC, request).await?;
        Ok(())
    }

    async fn send_shares(
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

    async fn collect_data<H: Digest + Clone>(
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
                        let entry = collected.entry(peer).or_default();
                        if entry.update_vss(vss) {
                            complete_count += 1;
                        }
                    }
                }

                Some(msg) = peers_rx.recv() => {
                    if let Some((peer, scalar_bytes)) = Request::get_dkg_scalar(msg) {
                        let scalar = Scalar::from_bytes(scalar_bytes.as_slice())?;
                        let entry = collected.entry(peer).or_default();
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
    ) -> Result<Vec<Secret<E>>> {
        data.iter()
            .map(|(peer, peer_share)| {
                if peer_share.validate(self_index) {
                    let scalar = peer_share
                        .scalar()
                        .expect("Scalar is missing, this should never happen");
                    Ok(Secret::from(scalar.clone()))
                } else {
                    error!("Failed to validate share from peer: {:?}", peer);
                    Err(Error::ValidateShare(*peer))
                }
            })
            .collect()
    }

    async fn receive<H: Digest + Clone>(
        &mut self,
        mut signer: Signer<E>,
        mut topic_rx: Receiver<Message>,
    ) -> JoinHandle<()> {
        const CHANNEL_SIZE: usize = 1000;
        let (to_self_tx, mut to_self_rx) = channel(CHANNEL_SIZE);

        let transport = self.transport.clone();
        let completed = self.completed.clone();
        let self_peer = self
            .peer
            .expect("Self peer is missing, this should never happen");
        self.to_self_tx = Some(to_self_tx);

        tokio::spawn(async move {
            let mut callback_tx: Option<oneshot::Sender<Signature<E>>> = None;

            loop {
                tokio::select! {
                    Some(msg) = topic_rx.recv() => {
                        // New DkG Generation
                        if let Some((message_id, _, msg_to_sign)) = Payload::get_dkg_sign(msg.clone()) {
                            let signature = signer.sign::<H>(message_id.to_string().as_bytes(), &msg_to_sign);
                            let payload = Payload::DkgSignResponse(signature.clone().into());
                            Self::publish(&transport, payload).await;
                            if let Some(signature) = signer.update::<H>(signature, self_peer) {
                                if let Some(tx) = callback_tx.take() {
                                    if let Err(e) = tx.send(signature.clone()) {
                                        error!("Failed to send signature to self: {:?}", e);
                                    }
                                }
                                Self::publish_final_signature(&transport, signature, completed.clone()).await;
                            }
                        }

                        // Collect existing DKG Generation
                        if let Some((peer, signature)) = Payload::get_dkg_sign_response(msg) {
                            let signature = Signature::from(signature.as_slice());
                            if let Some(signature) = signer.update::<H>(signature, peer) {
                                if let Some(tx) = callback_tx.take() {
                                    if let Err(e) = tx.send(signature.clone()) {
                                        error!("Failed to send signature to self: {:?}", e);
                                    }
                                }
                                Self::publish_final_signature(&transport, signature, completed.clone()).await;
                            }
                        }
                    }
                    // New DKG Generation from self
                    Some((msg_id, msg_to_sign, tx)) = to_self_rx.recv() => {
                        callback_tx = Some(tx);
                        let signature = signer.sign::<H>(msg_id.to_string().as_bytes(), &msg_to_sign);
                        let payload = Payload::DkgSign(msg_to_sign);
                        Self::publish(&transport, payload).await;
                        if let Some(signature) = signer.update::<H>(signature, self_peer) {
                            if let Some(tx) = callback_tx.take() {
                                if let Err(e) = tx.send(signature.clone()) {
                                    error!("Failed to send signature to self: {:?}", e);
                                }
                            }
                            Self::publish_final_signature(&transport, signature, completed.clone()).await;
                        }
                    }
                    else => {
                        error!("Channel is closed");
                        break;
                    }
                }
            }
        })
    }

    async fn publish(transport: &Arc<T>, payload: Payload) {
        if let Err(e) = transport.publish(DKG_TOPIC, payload).await {
            error!("Failed to publish payload: {:?}", e);
        }
    }

    async fn publish_final_signature(
        transport: &Arc<T>,
        signature: Signature<E>,
        completed: Arc<Mutex<HashMap<Vec<u8>, Signature<E>>>>,
    ) {
        let r_pub_key = signature
            .random_pub_key()
            .expect("Random public key is missing");
        let payload = Payload::DkgSignFinal(signature.clone().into());
        Self::publish(transport, payload).await;
        completed
            .lock()
            .await
            .insert(r_pub_key.to_bytes(), signature);
    }

    pub async fn stop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();

            self.to_self_tx = None;
        }
    }

    pub async fn sign(&self, msg_to_sign: Vec<u8>) -> Result<Signature<E>> {
        let payload = Payload::DkgSign(msg_to_sign.clone());
        let message_id = self.transport.publish(DKG_TOPIC, payload.clone()).await?;
        let (tx, rx) = oneshot::channel();

        if let Some(to_self_tx) = &self.to_self_tx {
            to_self_tx
                .send((message_id, msg_to_sign, tx))
                .await
                .map_err(|e| Error::Send(e.to_string()))?;
        }

        match timeout(self.config.timeout, rx).await {
            Ok(Ok(signature)) => Ok(signature),
            Ok(Err(e)) => Err(Error::from(e)),
            Err(_) => Err(Error::Timeout),
        }
    }

    pub fn pub_key(&self) -> Option<&PublicKey<E>> {
        self.pub_key.as_ref()
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
            .with_publish_cb(|_, _| MessageId::from(MESSAGE_ID), 4)
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
            timeout,
            threshold_counter,
            ..Default::default()
        }
    }

    fn threshold_counter(n: u16) -> u16 {
        (2 * n / 3) + 1
    }

    async fn create_classic(n: u16) -> (Classic<MockTransport, E>, PeerId, HashSet<PeerId>) {
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
        let mut classic = Classic::<_, E>::new(transport, config);

        let result = classic.start::<H>(self_peer, other_peers).await;

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

        let result = Classic::<_, E>::new(Arc::new(transport), config)
            .start::<H>(self_peer, other_peers)
            .await;

        assert!(
            result.is_err(),
            "Classic DKG instance should not be created due to timeout"
        );
    }

    #[tokio::test]
    async fn stop() {
        let (mut classic, self_peer, other_peers) = create_classic(NUM_PEERS).await;

        classic.start::<H>(self_peer, other_peers).await.unwrap();
        classic.stop().await;

        assert!(
            classic.handle.is_none(),
            "Classic DKG instance is still running"
        );
    }

    #[tokio::test]
    async fn sign() {
        const MESSAGE: &[u8] = b"MESSAGE";

        let (mut classic, self_peer, other_peers) = create_classic(NUM_PEERS).await;
        // We use it because we only have 1
        // real peer in the test, if we use the default threshold_counter, the test will fail
        classic.config.threshold_counter = Box::new(|_| 1);

        classic.start::<H>(self_peer, other_peers).await.unwrap();
        let result = classic.sign(MESSAGE.to_vec()).await;

        assert!(
            result.is_ok(),
            "Failed to sign message: {:?}",
            result.err().unwrap()
        );
    }
}
