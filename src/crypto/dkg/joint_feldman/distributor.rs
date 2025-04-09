use std::marker::PhantomData;
use std::sync::Arc;

use crate::{
    crypto::primitives::algebra::element::{Public, Secret},
    network::transport::{
        libp2p_transport::protocols::{gossipsub, request_response::payload::Request},
        Transport,
    },
};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Transport(String),
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

    pub async fn send_shares(&self, peers: &[libp2p::PeerId], id: &[u8], shares: &[SK]) {
        assert_eq!(peers.len(), shares.len(), "IDs and shares length mismatch");

        for (peer, share) in peers.iter().zip(shares.iter()) {
            let request = Request::VSSShare {
                id: id.to_vec(),
                share: share.to_vec(),
            };
            self.transport.request(peer, request).await;
        }
    }

    pub async fn publish_commitments(&self, id: &[u8], commitments: &[PK]) -> Result<()> {
        let commitments_bytes = commitments
            .iter()
            .map(|commitment| commitment.to_vec())
            .collect::<Vec<_>>();

        let payload = gossipsub::Payload::VSSCommitments {
            id: id.to_vec(),
            commitments: commitments_bytes,
        };

        self.transport
            .publish(&self.topic, payload)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        Ok(())
    }
}
