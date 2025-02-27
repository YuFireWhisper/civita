use libp2p::{
    gossipsub::{self, MessageAuthenticity},
    identity::Keypair,
    kad::{self, store::MemoryStore},
    swarm::NetworkBehaviour,
    PeerId,
};

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "P2PEvent")]
pub struct P2PBehaviour {
    gossipsub: gossipsub::Behaviour,
    kad: kad::Behaviour<MemoryStore>,
}

impl P2PBehaviour {
    pub fn new(keypair: Keypair) -> Self {
        let peer_id = Self::create_peer_id(&keypair);

        let gossipsub = Self::create_gossipsub(keypair.clone());
        let kad = Self::create_kad(peer_id);

        Self { gossipsub, kad }
    }

    fn create_gossipsub(keypair: Keypair) -> gossipsub::Behaviour {
        let config = Self::create_gossipsub_config();
        gossipsub::Behaviour::new(MessageAuthenticity::Signed(keypair), config).unwrap()
    }

    fn create_gossipsub_config() -> gossipsub::Config {
        gossipsub::ConfigBuilder::default().build().unwrap()
    }

    fn create_peer_id(keypair: &Keypair) -> PeerId {
        PeerId::from_public_key(&keypair.public())
    }

    fn create_kad(peer_id: PeerId) -> kad::Behaviour<MemoryStore> {
        kad::Behaviour::new(peer_id, MemoryStore::new(peer_id))
    }
}

enum P2PEvent {
    Gossipsub(gossipsub::Event),
    Kad(kad::Event),
}

impl From<gossipsub::Event> for P2PEvent {
    fn from(event: gossipsub::Event) -> Self {
        P2PEvent::Gossipsub(event)
    }
}

impl From<kad::Event> for P2PEvent {
    fn from(event: kad::Event) -> Self {
        P2PEvent::Kad(event)
    }
}

#[cfg(test)]
mod tests {}
