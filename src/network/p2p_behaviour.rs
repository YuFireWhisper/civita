use std::time::Duration;

use libp2p::{
    gossipsub::{self, MessageAuthenticity},
    identity::Keypair,
    kad::{self, store::MemoryStore},
    swarm::NetworkBehaviour,
    PeerId,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to create gossipsub behaviour: {0}")]
    Gossipsub(String),
    #[error("{0}")]
    GossipsubConfigBuilder(#[from] gossipsub::ConfigBuilderError),
}

type P2PBehaviourResult<T> = std::result::Result<T, Error>;

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "P2PEvent")]
pub struct P2PBehaviour {
    gossipsub: gossipsub::Behaviour,
    kad: kad::Behaviour<MemoryStore>,
}

impl P2PBehaviour {
    const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);

    pub fn new(keypair: Keypair) -> P2PBehaviourResult<Self> {
        let peer_id = Self::create_peer_id(&keypair);

        let gossipsub = Self::create_gossipsub(keypair.clone())?;
        let kad = Self::create_kad(peer_id);

        Ok(Self { gossipsub, kad })
    }

    fn create_gossipsub(keypair: Keypair) -> P2PBehaviourResult<gossipsub::Behaviour> {
        let config = Self::create_gossipsub_config()?;
        let behaviour = gossipsub::Behaviour::new(MessageAuthenticity::Signed(keypair), config)?;
        Ok(behaviour)
    }

    fn create_gossipsub_config() -> P2PBehaviourResult<gossipsub::Config> {
        let config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Self::HEARTBEAT_INTERVAL)
            .build()?;
        Ok(config)
    }

    fn create_peer_id(keypair: &Keypair) -> PeerId {
        PeerId::from_public_key(&keypair.public())
    }

    fn create_kad(peer_id: PeerId) -> kad::Behaviour<MemoryStore> {
        kad::Behaviour::new(peer_id, MemoryStore::new(peer_id))
    }

    pub fn gossipsub(&self) -> &gossipsub::Behaviour {
        &self.gossipsub
    }

    pub fn kad(&self) -> &kad::Behaviour<MemoryStore> {
        &self.kad
    }

    pub fn gossipsub_mut(&mut self) -> &mut gossipsub::Behaviour {
        &mut self.gossipsub
    }

    pub fn kad_mut(&mut self) -> &mut kad::Behaviour<MemoryStore> {
        &mut self.kad
    }
}

pub enum P2PEvent {
    Gossipsub(Box<gossipsub::Event>),
    Kad(kad::Event),
}

impl From<&str> for Error {
    fn from(err: &str) -> Self {
        Error::Gossipsub(err.to_string())
    }
}

impl From<gossipsub::Event> for P2PEvent {
    fn from(event: gossipsub::Event) -> Self {
        P2PEvent::Gossipsub(Box::new(event))
    }
}

impl From<kad::Event> for P2PEvent {
    fn from(event: kad::Event) -> Self {
        P2PEvent::Kad(event)
    }
}

#[cfg(test)]
mod tests {}
