use std::sync::Arc;

use libp2p::{identity::Keypair, Multiaddr, PeerId};

use crate::network::{request_response::RequestResponse, Gossipsub};

mod network;

pub use network::Config as NetworkConfig;

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Network(#[from] network::Error),
}

pub enum Transport {
    Network(network::Transport),
}

impl Transport {
    pub async fn new_network(
        keypair: Keypair,
        listen_addr: Multiaddr,
        config: NetworkConfig,
    ) -> Result<Self> {
        network::Transport::new(keypair, listen_addr, config)
            .await
            .map(Transport::Network)
            .map_err(Error::from)
    }

    pub async fn dial(&self, peer_id: PeerId, addr: Multiaddr) -> Result<()> {
        match self {
            Transport::Network(transport) => {
                transport.dial(peer_id, addr).await.map_err(Error::from)
            }
        }
    }

    pub async fn disconnect(&self, peer_id: PeerId) -> Result<()> {
        match self {
            Transport::Network(transport) => {
                transport.disconnect(peer_id).await.map_err(Error::from)
            }
        }
    }

    pub fn local_peer_id(&self) -> PeerId {
        match self {
            Transport::Network(transport) => transport.local_peer_id(),
        }
    }

    pub fn listen_addr(&self) -> Multiaddr {
        match self {
            Transport::Network(transport) => transport.listen_addr(),
        }
    }

    pub fn gossipsub(&self) -> Arc<Gossipsub> {
        match self {
            Transport::Network(transport) => transport.gossipsub(),
        }
    }

    pub fn request_response(&self) -> Arc<RequestResponse> {
        match self {
            Transport::Network(transport) => transport.request_response(),
        }
    }
}
