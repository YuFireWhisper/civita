use std::sync::Arc;
use std::{collections::HashMap, marker::PhantomData};

use crate::crypto;
use crate::crypto::dkg::joint_feldman::peer_info::PeerRegistry;
use crate::crypto::primitives::vss::Shares;
use crate::{
    crypto::primitives::algebra::element::{Public, Secret},
    network::transport::{libp2p_transport::protocols::gossipsub, Transport},
};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Transport(String),

    #[error("Keypair error: {0}")]
    Keypair(#[from] crypto::keypair::Error),

    #[error("Share not found for peer index: {0}")]
    ShareNotFound(u16),

    #[error("Public key not found for peer index: {0}")]
    PublicKeyNotFound(u16),
}

pub struct Distributor<T, SK, PK>
where
    T: Transport + Send + Sync + 'static,
    SK: Secret,
    PK: Public,
{
    transport: Arc<T>,
    topic: String,
    _marker: PhantomData<(SK, PK)>,
}

impl<T, SK, PK> Distributor<T, SK, PK>
where
    T: Transport + Send + Sync + 'static,
    SK: Secret,
    PK: Public,
{
    pub fn new(transport: Arc<T>, topic: &str) -> Self {
        Self {
            transport,
            topic: topic.to_string(),
            _marker: PhantomData,
        }
    }

    pub async fn send_shares(
        &self,
        id: Vec<u8>,
        peers: &PeerRegistry,
        mut shares: Shares,
    ) -> Result<()> {
        assert_eq!(
            peers.len() - 1, // Exclude self
            shares.shares.len(),
            "Number of peers must match the number of shares"
        );

        shares.shares = peers
            .indices()
            .map(|index| {
                let share = shares
                    .shares
                    .get(index)
                    .ok_or(Error::ShareNotFound(*index))?;

                let public_key = peers
                    .get_public_key_by_index(*index)
                    .ok_or(Error::PublicKeyNotFound(*index))?;

                Ok((*index, public_key.encrypt(share)?))
            })
            .collect::<Result<HashMap<_, _>>>()?;

        self.transport
            .publish(&self.topic, gossipsub::Payload::VSSShares { id, shares })
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;

        Ok(())
    }
}
