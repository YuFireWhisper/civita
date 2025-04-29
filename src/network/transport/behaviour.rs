use std::time::Duration;

use libp2p::{
    gossipsub::{self, MessageAuthenticity},
    identity::Keypair,
    kad,
    request_response::{self, cbor},
    swarm::NetworkBehaviour,
    PeerId, StreamProtocol,
};
use thiserror::Error;

use crate::network::transport::protocols::{
    kad::validated_store::ValidatedStore,
    request_response::payload::{Request, Response},
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to create gossipsub behaviour: {0}")]
    Gossipsub(String),
    #[error("{0}")]
    GossipsubConfigBuilder(#[from] gossipsub::ConfigBuilderError),
}

type BehaviourResult<T> = std::result::Result<T, Error>;

type CborBehaviour = cbor::Behaviour<Request, Response>;
type RequestResponseEvent = request_response::Event<Request, Response>;

#[derive(Debug)]
pub enum Event {
    Gossipsub(Box<gossipsub::Event>),
    Kad(kad::Event),
    RequestResponse(RequestResponseEvent),
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "Event")]
pub struct Behaviour {
    gossipsub: gossipsub::Behaviour,
    kad: kad::Behaviour<ValidatedStore>,
    request_response: CborBehaviour,
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

    fn create_kad(peer_id: PeerId) -> kad::Behaviour<ValidatedStore> {
        kad::Behaviour::new(peer_id, ValidatedStore::default())
    }

    fn create_request_response() -> cbor::Behaviour<Request, Response> {
        cbor::Behaviour::new(
            std::iter::once((
                StreamProtocol::new(Self::PROTOCOL_NAME),
                request_response::ProtocolSupport::Full,
            )),
            request_response::Config::default(),
        )
    }

    pub fn gossipsub(&self) -> &gossipsub::Behaviour {
        &self.gossipsub
    }

    pub fn kad(&self) -> &kad::Behaviour<ValidatedStore> {
        &self.kad
    }

    pub fn gossipsub_mut(&mut self) -> &mut gossipsub::Behaviour {
        &mut self.gossipsub
    }

    pub fn kad_mut(&mut self) -> &mut kad::Behaviour<ValidatedStore> {
        &mut self.kad
    }

    pub fn request_response(&self) -> &cbor::Behaviour<Request, Response> {
        &self.request_response
    }

    pub fn request_response_mut(&mut self) -> &mut CborBehaviour {
        &mut self.request_response
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
        Event::Kad(event)
    }
}

impl From<RequestResponseEvent> for Event {
    fn from(event: RequestResponseEvent) -> Self {
        Event::RequestResponse(event)
    }
}

#[cfg(test)]
mod tests {}
