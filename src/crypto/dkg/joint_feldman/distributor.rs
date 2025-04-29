use std::sync::Arc;

use crate::{
    crypto::{
        algebra::Point,
        index_map::IndexedMap,
        keypair,
        vss::{
            decrypted_share::DecryptedShares,
            encrypted_share::{self, EncryptedShares},
        },
    },
    network::transport::{libp2p_transport::protocols::gossipsub, Transport},
};

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
}

pub struct Distributor<T: Transport + 'static> {
    transport: Arc<T>,
    topic: String,
}

impl<T: Transport + 'static> Distributor<T> {
    pub fn new(transport: Arc<T>, topic: &str) -> Self {
        Self {
            transport,
            topic: topic.to_string(),
        }
    }

    pub async fn send_shares(
        &self,
        id: Vec<u8>,
        peer_pks: &IndexedMap<libp2p::PeerId, keypair::PublicKey>,
        decrypted_shares: &DecryptedShares,
        commitments: Vec<Point>,
    ) -> Result<()> {
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

    use crate::{
        crypto::{
            algebra::Scheme, dkg::joint_feldman::distributor::Distributor, index_map::IndexedMap,
            keypair, vss::Vss,
        },
        mocks::MockError,
        network::transport::MockTransport,
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

    fn generate_peers(nums: u16) -> IndexedMap<libp2p::PeerId, keypair::PublicKey> {
        let mut peers_map = IndexedMap::new();

        for _ in 0..nums {
            let peer_id = libp2p::PeerId::random();
            let public_key = keypair::generate_secp256k1().1;
            peers_map.insert(peer_id, public_key);
        }

        peers_map
    }

    #[tokio::test]
    async fn send_shares_success_valid_input() {
        let mut transport = MockTransport::new();
        transport
            .expect_publish()
            .with(eq(TOPIC.to_string()), always())
            .times(1)
            .returning(|_, _| Ok(create_message_id()));

        let distributor = Distributor::new(Arc::new(transport), TOPIC);
        let peers = generate_peers(NUM_PEERS);
        let (shares, commitments) = Vss::share(&DEFAULT_SCHEME, THRESHOLD, NUM_PEERS);

        let result = distributor
            .send_shares(ID.to_vec(), &peers, &shares, commitments)
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
        let transport = MockTransport::new();
        let distributor = Distributor::new(Arc::new(transport), TOPIC);

        let peers = generate_peers(NUM_PEERS - 1);
        let (shares, commitments) = Vss::share(&DEFAULT_SCHEME, THRESHOLD, NUM_PEERS);

        let _ = distributor
            .send_shares(ID.to_vec(), &peers, &shares, commitments)
            .await; // This should panic
    }

    #[tokio::test]
    async fn returns_error_transport_error() {
        let mut transport = MockTransport::new();
        transport
            .expect_publish()
            .with(eq(TOPIC.to_string()), always())
            .times(1)
            .returning(|_, _| Err(MockError));

        let distributor = Distributor::new(Arc::new(transport), TOPIC);
        let peers = generate_peers(NUM_PEERS);
        let (shares, commitments) = Vss::share(&DEFAULT_SCHEME, THRESHOLD, NUM_PEERS);

        let result = distributor
            .send_shares(ID.to_vec(), &peers, &shares, commitments)
            .await;

        assert!(
            result.is_err(),
            "Expected send_shares to fail, but it succeeded",
        );
    }
}
