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
}

type ResidentNetworkResult<T> = Result<T, ResidentNetworkError>;

pub struct ResidentNetwork {
    swarm: Swarm<ResidentNetworkBehaviour>,
}

impl ResidentNetwork {
    pub fn new(peer_id: PeerId, keypair: Keypair, multiaddr: Multiaddr) -> Self {
        let transport = tcp::tokio::Transport::default()
            .upgrade(Version::V1)
            .authenticate(noise::Config::new(&keypair).unwrap())
            .multiplex(yamux::Config::default())
            .boxed();

        let behaviour = ResidentNetworkBehaviour::new(peer_id);
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
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "ResidentNetworkEvent")]
pub struct ResidentNetworkBehaviour {
    kad: kad::Behaviour<MemoryStore>,
}

impl ResidentNetworkBehaviour {
    fn new(peer_id: PeerId) -> Self {
        let memory_store = MemoryStore::new(peer_id);
        Self {
            kad: kad::Behaviour::new(peer_id, memory_store),
        }
    }
}

#[derive(Debug)]
pub enum ResidentNetworkEvent {
    Kad(kad::Event),
}

impl From<kad::Event> for ResidentNetworkEvent {
    fn from(event: kad::Event) -> Self {
        Self::Kad(event)
    }
}

#[cfg(test)]
mod tests {
    use crate::core::resident_network::ResidentNetworkEvent;

    use super::{ResidentNetwork, ResidentNetworkBehaviour};
    use libp2p::{
        futures::StreamExt, identity::Keypair, swarm::SwarmEvent, Multiaddr, PeerId, Swarm,
    };
    use std::time::Duration;
    use tokio::time::timeout;

    pub struct TestFixtures {
        multiaddr: Multiaddr,
        keypair: Keypair,
    }

    impl TestFixtures {
        fn new() -> Self {
            let multiaddr = "/ip4/0.0.0.0/tcp/0".parse().unwrap();
            let keypair = Keypair::generate_ed25519();

            Self { multiaddr, keypair }
        }
    }

    #[tokio::test]
    async fn test_new() {
        let peer_id = PeerId::random();
        let fixtures = TestFixtures::new();

        let mut resident_network =
            super::ResidentNetwork::new(peer_id, fixtures.keypair, fixtures.multiaddr);

        assert!(resident_network.swarm.next().await.is_some());
    }

    #[tokio::test]
    async fn test_dial_success() {
        let (target_swarm, target_addr) = create_test_swarm().await;
        let target_peer_id = *target_swarm.local_peer_id();

        let fixtures = TestFixtures::new();
        let source_peer_id = PeerId::random();
        let mut source_network =
            ResidentNetwork::new(source_peer_id, fixtures.keypair, fixtures.multiaddr);

        let result = source_network
            .dial(target_peer_id, target_addr.clone())
            .await;
        assert!(result.is_ok(), "Dial should succeed");

        timeout(Duration::from_secs(1), async {
            while let Some(event) = source_network.swarm.next().await {
                if let SwarmEvent::Behaviour(ResidentNetworkEvent::Kad(_)) = event {
                    break;
                }
            }
        })
        .await
        .unwrap_or(());

        let kbuckets = source_network
            .swarm
            .behaviour_mut()
            .kad
            .kbucket(target_peer_id);
        if let Some(entry) = kbuckets {
            let addresses: Vec<Multiaddr> = entry
                .iter()
                .flat_map(|e| e.node.value.clone().into_vec())
                .collect();
            assert!(!addresses.is_empty(), "Should have at least one address");

            let base_address = addresses[0]
                .iter()
                .take_while(|p| !matches!(p, libp2p::core::multiaddr::Protocol::P2p(_)))
                .collect::<Multiaddr>();

            assert_eq!(
                base_address, target_addr,
                "Address should match the dialed address"
            );
        } else {
            panic!("No kbucket entry found for target peer");
        }
    }

    async fn create_test_swarm() -> (Swarm<ResidentNetworkBehaviour>, Multiaddr) {
        let fixtures = TestFixtures::new();
        let peer_id = PeerId::random();
        let mut network =
            ResidentNetwork::new(peer_id, fixtures.keypair, fixtures.multiaddr.clone());

        let listen_addr = timeout(Duration::from_secs(1), async {
            while let Some(event) = network.swarm.next().await {
                if let SwarmEvent::NewListenAddr { address, .. } = event {
                    return address;
                }
            }
            panic!("Failed to get listen address");
        })
        .await
        .unwrap();

        (network.swarm, listen_addr)
    }
}
