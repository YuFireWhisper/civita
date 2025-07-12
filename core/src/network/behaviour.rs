use libp2p::{
    gossipsub::{self, MessageAuthenticity},
    identity::Keypair,
    kad::{self, store::MemoryStore},
    swarm::NetworkBehaviour,
    PeerId,
};

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Gossipsub(String),

    #[error("{0}")]
    GossipsubConfigBuilder(#[from] gossipsub::ConfigBuilderError),
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
pub enum Event {
    Gossipsub(Box<gossipsub::Event>),
    Kad(Box<kad::Event>),
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "Event")]
pub struct Behaviour {
    gossipsub: gossipsub::Behaviour,
    kad: kad::Behaviour<MemoryStore>,
}

impl Behaviour {
    pub fn new(key: Keypair, peer_id: PeerId) -> Result<Self> {
        let gossipsub = Self::create_gossipsub(key)?;
        let kad = Self::create_kad(peer_id);

        Ok(Self { gossipsub, kad })
    }

    fn create_gossipsub(key: Keypair) -> Result<gossipsub::Behaviour> {
        let config = Self::create_gossipsub_config()?;
        let behaviour = gossipsub::Behaviour::new(MessageAuthenticity::Signed(key), config)?;
        Ok(behaviour)
    }

    fn create_gossipsub_config() -> Result<gossipsub::Config> {
        gossipsub::ConfigBuilder::default()
            .build()
            .map_err(Error::from)
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

impl From<&str> for Error {
    fn from(err: &str) -> Self {
        Error::Gossipsub(err.to_string())
    }
}

impl From<gossipsub::Event> for Event {
    fn from(event: gossipsub::Event) -> Self {
        Event::Gossipsub(Box::new(event))
    }
}

impl From<kad::Event> for Event {
    fn from(event: kad::Event) -> Self {
        Event::Kad(Box::new(event))
    }
}

#[cfg(test)]
mod tests {}
