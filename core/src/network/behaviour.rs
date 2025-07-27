use libp2p::{
    gossipsub::{self, MessageAuthenticity},
    identity::Keypair,
    kad::{self, store::MemoryStore},
    request_response::{self, cbor::codec::Codec, ProtocolSupport},
    swarm::NetworkBehaviour,
    PeerId, StreamProtocol,
};

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Gossipsub(String),
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
pub enum Event {
    Gossipsub(Box<gossipsub::Event>),
    Kad(Box<kad::Event>),
    RequestResponse(Box<request_response::Event<Vec<u8>, Vec<u8>>>),
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "Event")]
pub struct Behaviour {
    gossipsub: gossipsub::Behaviour,
    kad: kad::Behaviour<MemoryStore>,
    req_resp: request_response::Behaviour<Codec<Vec<u8>, Vec<u8>>>,
}

impl Behaviour {
    pub fn new(key: Keypair, peer_id: PeerId) -> Result<Self> {
        let gossipsub = Self::create_gossipsub(key)?;
        let kad = Self::create_kad(peer_id);
        let req_resp = Self::create_req_resp();

        Ok(Self {
            gossipsub,
            kad,
            req_resp,
        })
    }

    fn create_gossipsub(key: Keypair) -> Result<gossipsub::Behaviour> {
        let config = Self::create_gossipsub_config();
        let behaviour = gossipsub::Behaviour::new(MessageAuthenticity::Signed(key), config)?;
        Ok(behaviour)
    }

    fn create_gossipsub_config() -> gossipsub::Config {
        gossipsub::Config::default()
    }

    fn create_kad(peer_id: PeerId) -> kad::Behaviour<MemoryStore> {
        kad::Behaviour::new(peer_id, MemoryStore::new(peer_id))
    }

    fn create_req_resp() -> request_response::Behaviour<Codec<Vec<u8>, Vec<u8>>> {
        let protocol_name = concat!("/", env!("CARGO_PKG_NAME"));
        let protocol = (StreamProtocol::new(protocol_name), ProtocolSupport::Full);
        request_response::Behaviour::new([protocol], request_response::Config::default())
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

    pub fn req_resp(&self) -> &request_response::Behaviour<Codec<Vec<u8>, Vec<u8>>> {
        &self.req_resp
    }

    pub fn req_resp_mut(&mut self) -> &mut request_response::Behaviour<Codec<Vec<u8>, Vec<u8>>> {
        &mut self.req_resp
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

impl From<request_response::Event<Vec<u8>, Vec<u8>>> for Event {
    fn from(event: request_response::Event<Vec<u8>, Vec<u8>>) -> Self {
        Event::RequestResponse(Box::new(event))
    }
}

#[cfg(test)]
mod tests {}
