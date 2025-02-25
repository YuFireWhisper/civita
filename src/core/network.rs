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
    use libp2p::{futures::StreamExt, identity::Keypair, Multiaddr, PeerId};

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
}
