pub mod info;
pub mod role;

use std::sync::Arc;

use libp2p::{identity::Keypair, Multiaddr, PeerId};
use thiserror::Error;

use crate::{
    crypto::vrf::{
        self,
        dvrf::{self},
        Vrf, VrfFactory,
    },
    network::transport::{
        self,
        libp2p_transport::{config::Config, Libp2pTransport},
        Transport,
    },
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Transport(#[from] transport::Error),
    #[error("{0}")]
    Vrf(#[from] vrf::Error),
}

type Result<T> = std::result::Result<T, Error>;

pub struct Resident {
    transport: Arc<dyn Transport>,
    vrf: Arc<dyn Vrf>,
}

impl Resident {
    pub async fn new(keypair: Keypair, listen_addr: Multiaddr) -> Result<Self> {
        let peer_id = PeerId::from_public_key(&keypair.public());
        let transport =
            Arc::new(Libp2pTransport::new(keypair, listen_addr, Config::default()).await?);
        let vrf = dvrf::Factory::new(transport.clone(), peer_id)
            .create_vrf()
            .await?;

        Ok(Self { transport, vrf })
    }
}

#[cfg(test)]
mod tests {
    use libp2p::{identity::Keypair, Multiaddr};

    use crate::resident::Resident;

    const TEST_LISTEN_ADDR: &str = "/ip4/127.0.0.1/tcp/0";

    fn create_keypair() -> Keypair {
        Keypair::generate_ed25519()
    }

    fn create_listen_addr() -> Multiaddr {
        TEST_LISTEN_ADDR.parse().unwrap()
    }

    #[tokio::test]
    async fn test_new() {
        let keypair = create_keypair();
        let listen_addr = create_listen_addr();
        let resident = Resident::new(keypair, listen_addr).await;

        assert!(resident.is_ok());
    }
}
