use libp2p::gossipsub::{self, IdentTopic, MessageAuthenticity};
use libp2p::{noise, swarm, yamux, Transport};

use libp2p::{
    core::upgrade::Version,
    identity::Keypair,
    kad::{self, store::MemoryStore},
    swarm::NetworkBehaviour,
    tcp, Multiaddr, PeerId, Swarm,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ResidentNetworkError {
    #[error("Failed to dial peer: {0}")]
    DialError(#[from] swarm::DialError),
    #[error("Gossipsub error: {0}")]
    GossipsubError(String),
}

type ResidentNetworkResult<T> = Result<T, ResidentNetworkError>;

pub struct ResidentNetwork {
    swarm: Swarm<ResidentNetworkBehaviour>,
}

impl ResidentNetwork {
    pub fn new(peer_id: PeerId, keypair: &Keypair, multiaddr: Multiaddr) -> Self {
        let transport = tcp::tokio::Transport::default()
            .upgrade(Version::V1)
            .authenticate(noise::Config::new(keypair).unwrap())
            .multiplex(yamux::Config::default())
            .boxed();

        let behaviour = ResidentNetworkBehaviour::new(peer_id, keypair);
        let swarm_config = swarm::Config::with_tokio_executor();
        let mut swarm = Swarm::new(transport, behaviour, peer_id, swarm_config);

        swarm.listen_on(multiaddr).unwrap();

        Self { swarm }
    }

    pub async fn dial(
        &mut self,
        peer_id: PeerId,
        multiaddr: Multiaddr,
    ) -> ResidentNetworkResult<()> {
        self.swarm
            .behaviour_mut()
            .kad
            .add_address(&peer_id, multiaddr.clone());

        self.swarm
            .dial(multiaddr)
            .map_err(ResidentNetworkError::DialError)?;

        Ok(())
    }

    pub fn subscribe(&mut self, topic: &str) -> ResidentNetworkResult<()> {
        let topic = IdentTopic::new(topic);
        self.swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&topic)
            .map_err(|e| ResidentNetworkError::GossipsubError(e.to_string()))?;
        Ok(())
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "ResidentNetworkEvent")]
pub struct ResidentNetworkBehaviour {
    kad: kad::Behaviour<MemoryStore>,
    gossipsub: gossipsub::Behaviour,
}

impl ResidentNetworkBehaviour {
    fn new(peer_id: PeerId, keypair: &Keypair) -> Self {
        let memory_store = MemoryStore::new(peer_id);
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(std::time::Duration::from_secs(1))
            .build()
            .expect("Valid Gossipsub config");
        let gossipsub = gossipsub::Behaviour::new(
            MessageAuthenticity::Signed(keypair.clone()),
            gossipsub_config,
        )
        .expect("Gossipsub initialization should succeed");

        Self {
            kad: kad::Behaviour::new(peer_id, memory_store),
            gossipsub,
        }
    }
}

#[derive(Debug)]
pub enum ResidentNetworkEvent {
    Kad(kad::Event),
    Gossipsub(Box<gossipsub::Event>),
}

impl From<kad::Event> for ResidentNetworkEvent {
    fn from(event: kad::Event) -> Self {
        Self::Kad(event)
    }
}

impl From<gossipsub::Event> for ResidentNetworkEvent {
    fn from(event: gossipsub::Event) -> Self {
        Self::Gossipsub(Box::new(event))
    }
}

#[cfg(test)]
mod tests {
    use crate::core::resident_network::ResidentNetworkEvent;

    use super::ResidentNetwork;
    use libp2p::{futures::StreamExt, identity::Keypair, swarm::SwarmEvent, Multiaddr, PeerId};
    use std::time::Duration;
    use tokio::time::timeout;

    const TIMEOUT_DURATION: Duration = Duration::from_secs(1);
    const TEST_TOPIC: &str = "test-topic";

    struct TestNetwork {
        peer_id: PeerId,
        multiaddr: Multiaddr,
        network: ResidentNetwork,
    }

    impl TestNetwork {
        async fn new() -> Self {
            let keypair = Keypair::generate_ed25519();
            let peer_id = PeerId::from_public_key(&keypair.public());
            let multiaddr: Multiaddr = "/ip4/0.0.0.0/tcp/0".parse().unwrap();

            let mut network = ResidentNetwork::new(peer_id, &keypair, multiaddr);

            let listen_addr = timeout(TIMEOUT_DURATION, async {
                while let Some(event) = network.swarm.next().await {
                    if let SwarmEvent::NewListenAddr { address, .. } = event {
                        return address;
                    }
                }
                panic!("Failed to get listen address within timeout");
            })
            .await
            .expect("Timeout waiting for listener to start");

            Self {
                peer_id,
                multiaddr: listen_addr,
                network,
            }
        }

        async fn wait_for_kad_event(&mut self) -> bool {
            (timeout(TIMEOUT_DURATION, async {
                while let Some(event) = self.network.swarm.next().await {
                    if let SwarmEvent::Behaviour(ResidentNetworkEvent::Kad(_)) = event {
                        return true;
                    }
                }
                false
            })
            .await)
                .unwrap_or(false)
        }

        fn has_peer_in_routing_table(&mut self, peer_id: &PeerId) -> bool {
            self.network
                .swarm
                .behaviour_mut()
                .kad
                .kbucket(*peer_id)
                .is_some()
        }
    }

    #[tokio::test]
    async fn test_new() {
        let _ = TestNetwork::new().await;
    }

    #[tokio::test]
    async fn test_dial() {
        let target = TestNetwork::new().await;
        let mut source = TestNetwork::new().await;

        let result = source
            .network
            .dial(target.peer_id, target.multiaddr.clone())
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
        let mut network1 = TestNetwork::new().await;
        let network2 = TestNetwork::new().await;

        network1
            .network
            .dial(network2.peer_id, network2.multiaddr.clone())
            .await
            .expect("Dial operation should succeed");

        network1.wait_for_kad_event().await;

        network1
            .network
            .subscribe(TEST_TOPIC)
            // should not fail
            .expect("Subscribe operation should succeed");
    }
}
