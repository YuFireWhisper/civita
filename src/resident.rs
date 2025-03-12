use libp2p::{identity::Keypair, Multiaddr};
use thiserror::Error;
use tokio::time::Duration;

use crate::network::{
    message::Message,
    transport::{self, Libp2pTransport},
};

pub mod malicious_behaviour;
pub mod requation_action;
pub mod resident_id;
pub mod resident_status;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Transport(#[from] transport::Error),
}

type ResidentResult<T> = std::result::Result<T, Error>;

pub struct Resident {
    transport: Libp2pTransport,
}

impl Resident {
    const DEFAULT_RECEIVE_TIMEOUT: Duration = Duration::from_secs(5);

    pub async fn new(keypair: Keypair, listen_addr: Multiaddr) -> ResidentResult<Self> {
        let transport = Libp2pTransport::new(keypair, listen_addr, Self::DEFAULT_RECEIVE_TIMEOUT)?;
        Ok(Self { transport })
    }

    fn handle_received_message(message: Message) {
        println!("Received message: {:?}", message);
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
