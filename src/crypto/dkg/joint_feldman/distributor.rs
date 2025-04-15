use std::sync::Arc;

use crate::{
    crypto::{
        dkg::joint_feldman::peer_registry::PeerRegistry,
        keypair,
        primitives::{
            algebra::Point,
            vss::{
                decrypted_share::DecryptedShares,
                encrypted_share::{self, EncryptedShares},
            },
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
        peers: &PeerRegistry,
        decrypted_shares: &DecryptedShares,
        commitments: Vec<Point>,
    ) -> Result<()> {
        assert_eq!(
            peers.len() - 1, // Exclude self
            decrypted_shares.len(),
            "Number of peers (excluding self) must match the number of shares"
        );

        let encrypted_shares =
            EncryptedShares::from_decrypted(decrypted_shares, peers.iter_index_keys())?;
        let payload = gossipsub::Payload::VSSBundle {
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
