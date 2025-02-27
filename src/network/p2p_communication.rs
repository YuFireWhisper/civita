use std::io;

use libp2p::{
    core::{muxing::StreamMuxerBox, transport::Boxed, upgrade::Version},
    identity::Keypair,
    noise,
    swarm::{self},
    tcp::tokio,
    yamux, Multiaddr, PeerId, Swarm, Transport,
};
use thiserror::Error;

use super::p2p_behaviour::P2PBehaviour;

#[derive(Debug, Error)]
pub enum P2PCommunicationError {
    #[error("Swarm Transport Error: {0}")]
    SwarmTransport(#[from] libp2p::TransportError<io::Error>),
}

type P2PCommunicationResult<T> = Result<T, P2PCommunicationError>;

pub struct P2PCommunication {
    swarm: Swarm<P2PBehaviour>,
}

impl P2PCommunication {
    pub fn new(keypair: Keypair, listen_addr: Multiaddr) -> P2PCommunicationResult<Self> {
        let transport = Self::create_transport(keypair.clone());
        let behaviour = P2PBehaviour::new(keypair.clone());

        let mut swarm = Swarm::new(
            transport,
            behaviour,
            PeerId::from_public_key(&keypair.public()),
            swarm::Config::with_tokio_executor(),
        );
        swarm.listen_on(listen_addr)?;

        Ok(Self { swarm })
    }

    fn create_transport(keypair: Keypair) -> Boxed<(PeerId, StreamMuxerBox)> {
        tokio::Transport::default()
            .upgrade(Version::V1)
            .authenticate(noise::Config::new(&keypair).unwrap())
            .multiplex(yamux::Config::default())
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use libp2p::{futures::StreamExt, identity::Keypair, swarm::SwarmEvent, Multiaddr, Swarm};
    use std::time::Duration;
    use tokio::time::timeout;

    use crate::network::{p2p_behaviour::P2PBehaviour, p2p_communication::P2PCommunication};

    const TIMEOUT_DURATION: Duration = Duration::from_secs(5);

    struct TestCommunication {
        p2p: P2PCommunication,
    }

    impl TestCommunication {
        async fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let keypair = Keypair::generate_ed25519();
            let listen_addr: Multiaddr = "/ip4/0.0.0.0/tcp/0".parse()?;

            let mut p2p = P2PCommunication::new(keypair, listen_addr)?;
            Self::wait_for_listen_addr(&mut p2p.swarm).await?;

            Ok(Self { p2p })
        }

        async fn wait_for_listen_addr(swarm: &mut Swarm<P2PBehaviour>) -> Result<(), &'static str> {
            timeout(TIMEOUT_DURATION, async {
                while let Some(event) = swarm.next().await {
                    if let SwarmEvent::NewListenAddr { .. } = event {
                        return Ok(());
                    }
                }
                Err("Timeout waiting for listen address")
            })
            .await
            .map_err(|_| "Timeout waiting for listen address")?
        }
    }

    #[tokio::test]
    async fn test_p2p_communication_creation() {
        let result = TestCommunication::new().await;
        assert!(
            result.is_ok(),
            "Failed to create P2PCommunication: {:?}",
            result.err()
        );
    }
}
