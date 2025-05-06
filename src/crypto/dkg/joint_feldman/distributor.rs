use std::sync::Arc;

use tokio::sync::MutexGuard;

use crate::{
    crypto::{
        algebra::Point,
        keypair,
        vss::{
            decrypted_share::DecryptedShares,
            encrypted_share::{self, EncryptedShares},
        },
    },
    network::transport::protocols::gossipsub,
    utils::IndexedMap,
};

#[cfg(not(test))]
use crate::network::transport::Transport;

#[cfg(test)]
use crate::network::transport::MockTransport as Transport;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Transport(String),

    #[error("Keypair error: {0}")]
    Keypair(#[from] keypair::Error),

    #[error("Encrypted share error: {0}")]
    EncryptedShare(#[from] encrypted_share::Error),

    #[error("Peer public keys is not set")]
    NoPeerPublicKeys,
}

pub struct Distributor {
    transport: Arc<Transport>,
    topic: String,
}

impl Distributor {
    pub fn new(transport: Arc<Transport>, topic: &str) -> Self {
        Self {
            transport,
            topic: topic.to_string(),
        }
    }

    pub async fn send_shares<'a>(
        &self,
        id: Vec<u8>,
        peer_pks: MutexGuard<'a, Option<IndexedMap<libp2p::PeerId, keypair::PublicKey>>>,
        decrypted_shares: &DecryptedShares,
        commitments: Vec<Point>,
    ) -> Result<()> {
        let peer_pks = peer_pks.as_ref().ok_or_else(|| Error::NoPeerPublicKeys)?;

        assert_eq!(
            peer_pks.len(),
            decrypted_shares.len(),
            "Number of peers must match the number of shares"
        );

        let encrypted_shares =
            EncryptedShares::from_decrypted(decrypted_shares, peer_pks.iter_indexed_values())?;

        let payload = gossipsub::Payload::VSSComponent {
            id,
            encrypted_shares,
            commitments,
        };

        self.transport
            .publish(&self.topic, payload)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use mockall::predicate::{always, eq};
    use tokio::sync::Mutex;

    use crate::{
        crypto::{
            algebra::Scheme, dkg::joint_feldman::distributor::Distributor, keypair, vss::Vss,
        },
        network::transport::{self, MockTransport},
        utils::IndexedMap,
    };

    const DEFAULT_SCHEME: Scheme = Scheme::Secp256k1;
    const TOPIC: &str = "test_topic";
    const NUM_PEERS: u16 = 3;
    const THRESHOLD: u16 = 2;
    const ID: [u8; 32] = [0; 32];

    fn create_message_id() -> libp2p::gossipsub::MessageId {
        const MESSAGE_ID: [u8; 32] = [0; 32];
        libp2p::gossipsub::MessageId::from(MESSAGE_ID)
    }

    fn generate_peers(nums: u16) -> Mutex<Option<IndexedMap<libp2p::PeerId, keypair::PublicKey>>> {
        let mut peers_map = IndexedMap::new();

        for _ in 0..nums {
            let peer_id = libp2p::PeerId::random();
            let public_key = keypair::generate_secp256k1().1;
            peers_map.insert(peer_id, public_key);
        }

        Mutex::new(Some(peers_map))
    }

    fn create_transport() -> MockTransport {
        let mut transport = MockTransport::default();
        transport
            .expect_publish()
            .with(eq(TOPIC.to_string()), always())
            .times(1)
            .returning(|_, _| Ok(create_message_id()));
        transport
    }

    #[tokio::test]
    async fn send_shares_success_valid_input() {
        let transport = create_transport();
        let distributor = Distributor::new(Arc::new(transport), TOPIC);

        let peers = generate_peers(NUM_PEERS);
        let peers = peers.lock().await;

        let (shares, commitments) = Vss::share(&DEFAULT_SCHEME, THRESHOLD, NUM_PEERS);

        let result = distributor
            .send_shares(ID.to_vec(), peers, &shares, commitments)
            .await;

        assert!(
            result.is_ok(),
            "Expected send_shares to succeed, but it failed: {:?}",
            result
        );
    }

    #[tokio::test]
    #[should_panic(expected = "Number of peers must match the number of shares")]
    async fn peers_count_validation_works() {
        let transport = create_transport();
        let distributor = Distributor::new(Arc::new(transport), TOPIC);

        let peers = generate_peers(NUM_PEERS - 1);
        let peers = peers.lock().await;

        let (shares, commitments) = Vss::share(&DEFAULT_SCHEME, THRESHOLD, NUM_PEERS);

        let _ = distributor
            .send_shares(ID.to_vec(), peers, &shares, commitments)
            .await; // This should panic
    }

    #[tokio::test]
    async fn returns_error_transport_error() {
        let mut transport = MockTransport::default();
        transport
            .expect_publish()
            .with(eq(TOPIC.to_string()), always())
            .times(1)
            .returning(|_, _| Err(transport::Error::MockError));

        let distributor = Distributor::new(Arc::new(transport), TOPIC);

        let peers = generate_peers(NUM_PEERS);
        let peers = peers.lock().await;

        let (shares, commitments) = Vss::share(&DEFAULT_SCHEME, THRESHOLD, NUM_PEERS);

        let result = distributor
            .send_shares(ID.to_vec(), peers, &shares, commitments)
            .await;

        assert!(
            result.is_err(),
            "Expected send_shares to fail, but it succeeded",
        );
    }

    #[tokio::test]
    async fn fail_no_peer_public_keys() {
        let transport = MockTransport::default();
        let distributor = Distributor::new(Arc::new(transport), TOPIC);

        let peers = Mutex::new(None);

        let (shares, commitments) = Vss::share(&DEFAULT_SCHEME, THRESHOLD, NUM_PEERS);

        let result = distributor
            .send_shares(ID.to_vec(), peers.lock().await, &shares, commitments)
            .await;

        assert!(
            result.is_err(),
            "Expected send_shares to fail due to no peer public keys"
        );
    }
}
