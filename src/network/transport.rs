use std::sync::Arc;

use libp2p::{Multiaddr, PeerId};

use crate::{
    crypto::SecretKey,
    network::{Gossipsub, Storage},
};

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
        sk: SecretKey,
        listen_addr: Multiaddr,
        config: NetworkConfig,
    ) -> Result<Self> {
        network::Transport::new(sk, listen_addr, config)
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

    pub fn secret_key(&self) -> &SecretKey {
        match self {
            Transport::Network(transport) => transport.secret_key(),
        }
    }

    pub fn gossipsub(&self) -> Arc<Gossipsub> {
        match self {
            Transport::Network(transport) => transport.gossipsub(),
        }
    }

    pub fn storage(&self) -> Arc<Storage> {
        match self {
            Transport::Network(transport) => transport.storage(),
        }
    }
}
