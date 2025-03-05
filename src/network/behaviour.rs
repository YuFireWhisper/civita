use std::time::Duration;

use libp2p::{
    gossipsub::{self, MessageAuthenticity},
    identity::Keypair,
    kad::{self, store::MemoryStore},
    request_response,
    swarm::NetworkBehaviour,
    PeerId,
};
use thiserror::Error;

use super::request_response::{Codec, Request, Response};

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to create gossipsub behaviour: {0}")]
    Gossipsub(String),
    #[error("{0}")]
    GossipsubConfigBuilder(#[from] gossipsub::ConfigBuilderError),
}

type BehaviourResult<T> = std::result::Result<T, Error>;

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "P2PEvent")]
pub struct Behaviour {
    gossipsub: gossipsub::Behaviour,
    kad: kad::Behaviour<MemoryStore>,
    request_response: request_response::Behaviour<Codec>,
}

impl Behaviour {
    const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);
    const PROTOCOL_NAME: &'static str = "/civita_protocol/1.0.0";

    pub fn new(keypair: Keypair) -> BehaviourResult<Self> {
        let peer_id = Self::create_peer_id(&keypair);

        let gossipsub = Self::create_gossipsub(keypair.clone())?;
        let kad = Self::create_kad(peer_id);
        let request_response = Self::create_request_response();

        Ok(Self {
            gossipsub,
            kad,
            request_response,
        })
    }

    fn create_gossipsub(keypair: Keypair) -> BehaviourResult<gossipsub::Behaviour> {
        let config = Self::create_gossipsub_config()?;
        let behaviour = gossipsub::Behaviour::new(MessageAuthenticity::Signed(keypair), config)?;
        Ok(behaviour)
    }

    fn create_gossipsub_config() -> BehaviourResult<gossipsub::Config> {
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

    fn create_request_response() -> request_response::Behaviour<Codec> {
        request_response::Behaviour::new(
            std::iter::once((Self::PROTOCOL_NAME, request_response::ProtocolSupport::Full)),
            Self::create_request_response_config(),
        )
    }

    fn create_request_response_config() -> request_response::Config {
        request_response::Config::default()
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

    pub fn request_response(&self) -> &request_response::Behaviour<Codec> {
        &self.request_response
    }
}

pub enum P2PEvent {
    Gossipsub(Box<gossipsub::Event>),
    Kad(kad::Event),
    RequestResponse(request_response::Event<Request, Response>),
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

impl From<request_response::Event<Request, Response>> for P2PEvent {
    fn from(event: request_response::Event<Request, Response>) -> Self {
        P2PEvent::RequestResponse(event)
    }
}

#[cfg(test)]
mod tests {}
