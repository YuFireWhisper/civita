use libp2p::{
    core::{muxing::StreamMuxerBox, transport::Boxed, upgrade::Version},
    identity::Keypair,
    noise,
    swarm::{self},
    tcp::tokio,
    yamux, Multiaddr, PeerId, Swarm, Transport,
};

use super::p2p_behaviour::P2PBehaviour;

pub struct P2PCommunication {
    swarm: Swarm<P2PBehaviour>,
}

impl P2PCommunication {
    pub fn new(keypair: Keypair, listen_addr: Multiaddr) -> Self {
        let transport = Self::create_transport(keypair.clone());
        let behaviour = P2PBehaviour::new(keypair.clone());

        let mut swarm = Swarm::new(
            transport,
            behaviour,
            PeerId::from_public_key(&keypair.public()),
            swarm::Config::with_tokio_executor(),
        );
        swarm.listen_on(listen_addr).unwrap();

        Self { swarm }
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
    use std::time::Duration;

    use crate::network::p2p_communication::P2PCommunication;
    use libp2p::{futures::StreamExt, identity::Keypair, swarm::SwarmEvent, Multiaddr};
    use tokio::time::timeout;

    const TIMEOUT_DURATION: Duration = Duration::from_secs(5);

    struct TestCommunication {
        p2p: P2PCommunication,
    }

    impl TestCommunication {
        async fn new() -> Result<Self, &'static str> {
            let keypair = Keypair::generate_ed25519();
            let listen_addr: Multiaddr = "/ip4/0.0.0.0/tcp/0".parse().unwrap();

            let mut p2p = P2PCommunication::new(keypair, listen_addr);

            let is_ready = timeout(TIMEOUT_DURATION, async {
                while let Some(event) = p2p.swarm.next().await {
                    if let SwarmEvent::NewListenAddr { .. } = event {
                        return true;
                    }
                }
                false
            })
            .await
            .map_err(|_| "Failed to create P2PCommunication")?;

            if is_ready {
                Ok(Self { p2p })
            } else {
                Err("Failed to create P2PCommunication")
            }
        }
    }

    #[tokio::test]
    async fn test_new() {
        assert!(
            TestCommunication::new().await.is_ok(),
            "Failed to create P2PCommunication"
        );
    }
}
