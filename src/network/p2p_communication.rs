use std::io;

use libp2p::{
    core::{muxing::StreamMuxerBox, transport::Boxed, upgrade::Version},
    gossipsub::IdentTopic,
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
    #[error("Transport Error: {0}")]
    Transport(#[from] libp2p::TransportError<io::Error>),
    #[error("Dial Error: {0}")]
    Dial(#[from] swarm::DialError),
    #[error("Gossipsub Error: {0}")]
    Gossipsub(String),
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

    pub async fn dial(&mut self, peer_id: PeerId, addr: Multiaddr) -> P2PCommunicationResult<()> {
        self.swarm
            .behaviour_mut()
            .kad_mut()
            .add_address(&peer_id, addr.clone());
        self.swarm.dial(addr)?;

        Ok(())
    }

    pub fn subscribe(&mut self, topic: &str) -> P2PCommunicationResult<()> {
        let topic = IdentTopic::new(topic);
        self.swarm
            .behaviour_mut()
            .gossipsub_mut()
            .subscribe(&topic)
            .map_err(|e| P2PCommunicationError::Gossipsub(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use libp2p::{
        futures::StreamExt, identity::Keypair, swarm::SwarmEvent, Multiaddr, PeerId, Swarm,
    };
    use std::time::Duration;
    use tokio::time::timeout;

    use crate::network::{p2p_behaviour::P2PBehaviour, p2p_communication::P2PCommunication};

    const TIMEOUT_DURATION: Duration = Duration::from_secs(5);
    const TEST_TOPIC: &str = "test_topic";

    struct TestCommunication {
        peer_id: PeerId,
        listen_addr: Multiaddr,
        p2p: P2PCommunication,
    }

    impl TestCommunication {
        pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let keypair = Keypair::generate_ed25519();
            let listen_addr: Multiaddr = "/ip4/0.0.0.0/tcp/0".parse()?;

            let mut p2p = P2PCommunication::new(keypair.clone(), listen_addr.clone())?;
            Self::wait_for_listen_addr(&mut p2p.swarm).await?;

            let peer_id = PeerId::from_public_key(&keypair.public());

            Ok(Self {
                peer_id,
                listen_addr,
                p2p,
            })
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

        pub fn has_peer_in_routing_table(&mut self, peer_id: &PeerId) -> bool {
            self.p2p
                .swarm
                .behaviour_mut()
                .kad_mut()
                .kbucket(*peer_id)
                .is_some()
        }

        pub async fn wait_for_kad_event(&mut self) -> bool {
            timeout(TIMEOUT_DURATION, async {
                while let Some(event) = self.p2p.swarm.next().await {
                    if let SwarmEvent::Behaviour(_) = event {
                        return true;
                    }
                }
                false
            })
            .await
            .unwrap_or(false)
        }
    }

    #[tokio::test]
    async fn test_new() {
        let result = TestCommunication::new().await;
        assert!(
            result.is_ok(),
            "Failed to create P2PCommunication: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_dial() {
        let target = TestCommunication::new().await.unwrap();
        let mut source = TestCommunication::new().await.unwrap();

        let result = source
            .p2p
            .dial(target.peer_id, target.listen_addr.clone())
            .await;
        let received_kad_event = source.wait_for_kad_event().await;

        assert!(result.is_ok(), "Dial operation should succeed");
        assert!(
            received_kad_event,
            "Should receive Kademlia event after dialing"
        );
        assert!(
            source.has_peer_in_routing_table(&target.peer_id),
            "Target peer should be in the routing table after dialing"
        );
    }

    #[tokio::test]
    async fn test_subscribe() {
        let mut comm = TestCommunication::new()
            .await
            .expect("Failed to create P2PCommunication");

        let subscribe_result = comm.p2p.subscribe(TEST_TOPIC);
        assert!(
            subscribe_result.is_ok(),
            "Failed to subscribe to topic: {:?}",
            subscribe_result.err()
        );

        let gossipsub = comm.p2p.swarm.behaviour_mut().gossipsub_mut();
        let subscriptions: Vec<String> =
            gossipsub.topics().map(|t| t.as_str().to_string()).collect();
        assert!(
            subscriptions.contains(&TEST_TOPIC.to_string()),
            "Should be subscribed to topic"
        );
    }
}
